(**************************************************************************)
(*                                BELENIOS                                *)
(*                                                                        *)
(*  Copyright © 2012-2014 Inria                                           *)
(*                                                                        *)
(*  This program is free software: you can redistribute it and/or modify  *)
(*  it under the terms of the GNU Affero General Public License as        *)
(*  published by the Free Software Foundation, either version 3 of the    *)
(*  License, or (at your option) any later version, with the additional   *)
(*  exemption that compiling, linking, and/or using OpenSSL is allowed.   *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful, but   *)
(*  WITHOUT ANY WARRANTY; without even the implied warranty of            *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *)
(*  Affero General Public License for more details.                       *)
(*                                                                        *)
(*  You should have received a copy of the GNU Affero General Public      *)
(*  License along with this program.  If not, see                         *)
(*  <http://www.gnu.org/licenses/>.                                       *)
(**************************************************************************)

open Serializable_builtin_j
open Serializable_j
open Signatures
open Common

module type PARAMS = sig
  val l : int
  val t : int
  val trustee_id : int
  val step : [ `Step1 | `Step2 ]
  module G : GROUP
end

let parse_args () = begin

  let group = ref None in

  let trustees = ref None in
  let trustee_id = ref None in
  let threshold = ref None in
  let step = ref `Step1 in

  let speclist = Arg.([
    "--group", String (fun s -> group := Some s), "file with group parameters";
    "--trustees", Int (fun x -> trustees := Some x), "number of trustees";
    "--threshold", Int (fun x -> threshold := Some x), "number of trustees needed to decrypt";
    "--trustee-id", Int (fun x -> trustee_id := Some x), "identifier of the trustee";
    "--second-step", Unit (fun () -> step := `Step2), "run second step";
  ]) in

  let usage_msg =
    Printf.sprintf "Usage: %s trustee-keygen --group <file> --trustees <n> --threshold <m> --trustee-id <i> [--second-step]" Sys.argv.(0)
  in

  let usage () =
    Arg.usage speclist usage_msg;
    exit 1
  in

  let anon_fun x =
    Printf.eprintf "I do not know what to do with %s\n" x;
    usage ()
  in

  let () = Arg.parse speclist anon_fun usage_msg in

  let group = match !group with
    | None ->
      Printf.eprintf "--group is missing!\n";
      usage ()
    | Some fname ->
      let ic = open_in fname in
      let ls = Yojson.init_lexer () in
      let lb = Lexing.from_channel ic in
      let r = Group.read ls lb in
      close_in ic;
      r
  in

  let module P = struct
    module G = (val group : GROUP)

    let l, t, trustee_id =
      match !trustees, !threshold, !trustee_id with
      | Some l, Some x, Some i -> l, x-1, i
      | _, _, _ ->
        Printf.eprintf "Threshold parameters are missing!\n";
        usage ()

    let step = !step
  end in

  (module P : PARAMS)

end

module Run (P : PARAMS) : EMPTY = struct
  open P

  (* Setup group *)

  module M = Election.MakeSimpleMonad(G);;

  (* Generate key *)

  let rec generate_poly degree =
    if degree < 0
    then M.return []
    else (
      let coeff = M.random G.q
      and coeffs = generate_poly (degree-1)
      in
      M.bind coeff (fun coeff ->
        M.bind coeffs (fun coeffs ->
          M.return (coeff :: coeffs)
        )
      )
    )

  let rec eval_poly p x =
    match p with
    | [] -> Z.zero
    | coeff :: coeffs -> Z.((x * eval_poly coeffs x + coeff) mod G.q)

  let () = match step with
    | `Step1 ->
      let i = trustee_id in
      let poly = generate_poly t () in
      let public_coeffs = List.map (fun x -> G.(g **~ x)) poly in
      let shared_secrets =
        seq 1 l |>
        List.map (fun j ->
          j, eval_poly poly (Z.of_int j)
        )
      in
      let () =
        let x = string_of_public_coeffs G.write {public_coeffs} in
        let oc = Printf.ksprintf open_out "public_coeffs_%d.json" i in
        output_string oc x;
        output_string oc "\n";
        close_out oc
      in
      let () =
        List.iter (fun (j, shared_secret) ->
          let x = string_of_shared_secret {shared_secret} in
          let oc = Printf.ksprintf open_out "shared_secret_%d_%d.json" i j in
          output_string oc x;
          output_string oc "\n";
          close_out oc
        ) shared_secrets
      in
      ()
    | `Step2 ->
      let j = trustee_id in
      let zj = Z.of_int j in
      let load_shared_secret i =
        let ic = Printf.ksprintf open_in "shared_secret_%d_%d.json" i j in
        let r = input_line ic in
        close_in ic;
        shared_secret_of_string r
      in
      let load_public_coeffs i =
        let ic = Printf.ksprintf open_in "public_coeffs_%d.json" i in
        let r = input_line ic in
        close_in ic;
        public_coeffs_of_string G.read r
      in
      let shared_secrets =
        seq 1 l |>
        List.map (fun i ->
          let {shared_secret} = load_shared_secret i in
          i, shared_secret
        )
      in
      let () =
        shared_secrets |>
        List.iter (fun (i, shared_secret) ->
          let {public_coeffs} = load_public_coeffs i in
          let left = G.(g **~ shared_secret) in
          let _, right =
            List.fold_left (fun (accu_j, accu_r) coeff ->
              Z.(accu_j * zj), G.(accu_r *~ (coeff **~ accu_j))
            ) (Z.one, G.one) public_coeffs
          in
          if not G.(left =~ right) then (
            Printf.ksprintf failwith
              "P_%d broadcasts a complaint against P_%d" j i
          )
        )
      in
      (* we assume that nobody complains *)
      let secret_share =
        List.map snd shared_secrets |>
        List.fold_left Z.( + ) Z.zero
      in
      let () =
        let x = string_of_secret_share {secret_share} in
        let oc = Printf.ksprintf open_out "secret_share_%d.json" j in
        output_string oc x;
        output_string oc "\n";
        close_out oc
      in
      ()

end


let main () =
  let module P = (val parse_args () : PARAMS) in
  let module X : EMPTY = Run (P) in
  ()
