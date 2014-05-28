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
  val uuid : Uuidm.t
  val template : template
  val l : int
  val t : int
  module G : GROUP
end

let parse_args () = begin

  let group = ref None in
  let uuid = ref None in
  let template = ref None in
  let trustees = ref None in
  let threshold = ref None in

  let speclist = Arg.([
    "--group", String (fun s -> group := Some s), "file with group parameters";
    "--uuid", String (fun s -> uuid := Some s), "UUID of the election";
    "--template", String (fun s -> template := Some s), "file with election template";
    "--trustees", Int (fun s -> trustees := Some s), "number of trustees";
    "--threshold", Int (fun s -> threshold := Some s), "number of trustees needed to decrypt";
  ]) in

  let usage_msg =
    Printf.sprintf "Usage: %s mkelection --group <file> --uuid <uuid> --template <file>" Sys.argv.(0)
  in

  let usage () =
    Arg.usage speclist usage_msg;
    exit 1
  in

  let die s = prerr_endline s; usage () in

  let anon_fun x =
    Printf.eprintf "I do not know what to do with %s\n" x;
    usage ()
  in

  let () = Arg.parse speclist anon_fun usage_msg in

  let group = match !group with
    | None -> die "--group is missing"
    | Some fname ->
      let ic = open_in fname in
      let ls = Yojson.init_lexer () in
      let lb = Lexing.from_channel ic in
      let r = Group.read ls lb in
      r
  in

  let module P = struct

    let uuid = match !uuid with
      | None -> die "--uuid is missing"
      | Some uuid -> match Uuidm.of_string uuid with
        | None -> die "invalid UUID"
        | Some u -> u

    let template = match !template with
      | None -> die "--template is missing"
      | Some fname ->
        let ic = open_in fname in
        let ls = Yojson.init_lexer () in
        let lb = Lexing.from_channel ic in
        let r = read_template ls lb in
        close_in ic;
        r

    let l, t =
      match !trustees, !threshold with
      | Some l, Some x -> l, x-1
      | _, _ ->
        Printf.eprintf "Threshold parameters are missing!\n";
        usage ()

    module G = (val group : GROUP)

    let write_params buf params =
      let y = params.e_public_key in
      let w = G.wrap_pubkey y in
      let params = { params with e_public_key = w } in
      write_params G.write_wrapped_pubkey buf params

  end in

  (module P : PARAMS)

end

module Run (P : PARAMS) : EMPTY = struct
  open P

  (* Setup group *)

  module M = Election.MakeSimpleMonad(G);;

  (* Setup trustees *)

  let load_public_coeffs i =
    let ic = Printf.ksprintf open_in "public_coeffs_%d.json" i in
    let r = input_line ic in
    close_in ic;
    public_coeffs_of_string G.read r

  let all_public_coeffs = seq 1 l |> List.map load_public_coeffs

  let verification_key j =
    let zj = Z.of_int j in
    all_public_coeffs |>
    List.map (fun {public_coeffs} ->
      let _, right =
        List.fold_left (fun (accu_j, accu_r) coeff ->
          Z.(accu_j * zj), G.(accu_r *~ (coeff **~ accu_j))
        ) (Z.one, G.one) public_coeffs
      in
      List.hd public_coeffs, right
    ) |> List.fold_left (fun (y, vk) (yi, exp_ij) ->
      G.(y *~ yi), G.(vk *~ exp_ij)
    ) (G.one, G.one)

  let all_vk = seq 1 l |> List.map verification_key

  let y =
    match all_vk with
    | [] -> assert false
    | (y, _) :: ys ->
      assert (List.for_all (fun (y', _) -> y' = y) ys);
      y

  let public_keys = all_vk |> List.map snd

  (* Setup election *)

  let params = {
    e_description = template.t_description;
    e_name = template.t_name;
    e_public_key = G.wrap_pubkey y;
    e_trustees = l;
    e_threshold = t+1;
    e_questions = template.t_questions;
    e_uuid = uuid;
    e_short_name = template.t_short_name;
  }

  (* Save to disk *)

  let write_params = write_params G.write_wrapped_pubkey
  let () = save_to "election.json" write_params params

  let () =
    let oc = open_out "public_keys.jsons" in
    List.iter (fun trustee_public_key ->
      let x = string_of_trustee_public_key G.write {trustee_public_key} in
      output_string oc x;
      output_string oc "\n"
    ) public_keys;
    close_out oc

end

let main () =
  let module P = (val parse_args () : PARAMS) in
  let module X : EMPTY = Run (P) in
  ()
