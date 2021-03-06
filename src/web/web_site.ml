(**************************************************************************)
(*                                BELENIOS                                *)
(*                                                                        *)
(*  Copyright © 2012-2016 Inria                                           *)
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

open Lwt
open Platform
open Serializable_builtin_t
open Serializable_j
open Signatures
open Common
open Web_serializable_builtin_t
open Web_serializable_j
open Web_common
open Web_services

let source_file = ref "belenios.tar.gz"
let maxmailsatonce = ref 1000

let ( / ) = Filename.concat

module PString = String

open Eliom_service
open Eliom_registration

(* Table with elections in setup mode. *)
let election_stable = Ocsipersist.open_table "site_setup"

(* Table with tokens given to trustees. *)
let election_pktokens = Ocsipersist.open_table "site_pktokens"

(* Table with tokens given to trustees (in threshold mode). *)
let election_tpktokens = Ocsipersist.open_table "site_tpktokens"

(* Table with tokens given to trustees (in threshold mode) to decrypt *)
let election_tokens_decrypt = Ocsipersist.open_table "site_tokens_decrypt"

(* Table with tokens given to credential authorities. *)
let election_credtokens = Ocsipersist.open_table "site_credtokens"

module T = Web_templates

let raw_find_election uuid =
  let%lwt raw_election = Web_persist.get_raw_election uuid in
  match raw_election with
  | Some raw_election ->
     return (Election.of_string raw_election)
  | _ -> Lwt.fail Not_found

module WCacheTypes = struct
  type key = uuid
  type value = Yojson.Safe.json election
end

module WCache = Ocsigen_cache.Make (WCacheTypes)

let find_election =
  let cache = new WCache.cache raw_find_election 100 in
  fun x -> cache#find x

let get_setup_election uuid =
  let%lwt se = Ocsipersist.find election_stable (raw_string_of_uuid uuid) in
  return (setup_election_of_string se)

let set_setup_election uuid se =
  Ocsipersist.add election_stable (raw_string_of_uuid uuid) (string_of_setup_election se)

let dump_passwords dir table =
  Lwt_io.(with_file Output (dir / "passwords.csv") (fun oc ->
    Ocsipersist.iter_step (fun voter (salt, hashed) ->
      write_line oc (voter ^ "," ^ salt ^ "," ^ hashed)
    ) table
  ))

let finalize_election uuid se =
  let uuid_s = raw_string_of_uuid uuid in
  (* voters *)
  let () =
    if se.se_voters = [] then failwith "no voters"
  in
  (* passwords *)
  let () =
    match se.se_metadata.e_auth_config with
    | Some [{auth_system = "password"; _}] ->
       if not @@ List.for_all (fun v -> v.sv_password <> None) se.se_voters then
         failwith "some passwords are missing"
    | _ -> ()
  in
  (* credentials *)
  let () =
    if not se.se_public_creds_received then
      failwith "public credentials are missing"
  in
  (* trustees *)
  let group = Group.of_string se.se_group in
  let module G = (val group : GROUP) in
  let%lwt y, trustees, pk_or_tp, private_keys =
    match se.se_threshold_trustees with
    | None ->
       let module KG = Trustees.MakeSimple (G) (LwtRandom) in
       let%lwt trustees, public_keys, private_key =
         match se.se_public_keys with
         | [] ->
            let%lwt private_key = KG.generate () in
            let%lwt public_key = KG.prove private_key in
            return (None, [public_key], `KEY private_key)
         | _ :: _ ->
            let private_key =
              List.fold_left (fun accu {st_private_key; _} ->
                  match st_private_key with
                  | Some x -> x :: accu
                  | None -> accu
                ) [] se.se_public_keys
            in
            let private_key = match private_key with
              | [] -> `None
              | [x] -> `KEY x
              | _ -> failwith "multiple private keys"
            in
            return (
                Some (List.map (fun {st_id; _} -> st_id) se.se_public_keys),
                (List.map
                   (fun {st_public_key; _} ->
                     if st_public_key = "" then failwith "some public keys are missing";
                     trustee_public_key_of_string G.read st_public_key
                   ) se.se_public_keys),
                private_key)
       in
       let y = KG.combine (Array.of_list public_keys) in
       return (y, trustees, `PK public_keys, private_key)
    | Some ts ->
       match se.se_threshold_parameters with
       | None -> failwith "key establishment not finished"
       | Some tp ->
          let tp = threshold_parameters_of_string G.read tp in
          let module P = Trustees.MakePKI (G) (LwtRandom) in
          let module C = Trustees.MakeChannels (G) (LwtRandom) (P) in
          let module K = Trustees.MakePedersen (G) (LwtRandom) (P) (C) in
          let trustees = List.map (fun {stt_id; _} -> stt_id) ts in
          let private_keys =
            List.map (fun {stt_voutput; _} ->
                match stt_voutput with
                | Some v ->
                   let voutput = voutput_of_string G.read v in
                   voutput.vo_private_key
                | None -> failwith "inconsistent state"
              ) ts
          in
          let y = K.combine tp in
          return (y, Some trustees, `TP tp, `KEYS private_keys)
  in
  (* election parameters *)
  let metadata = { se.se_metadata with e_trustees = trustees } in
  let template = se.se_questions in
  let params = {
    e_description = template.t_description;
    e_name = template.t_name;
    e_public_key = {wpk_group = G.group; wpk_y = y};
    e_questions = template.t_questions;
    e_uuid = uuid;
  } in
  let raw_election = string_of_params (write_wrapped_pubkey G.write_group G.write) params in
  (* write election files to disk *)
  let dir = !spool_dir / uuid_s in
  let create_file fname what xs =
    Lwt_io.with_file
      ~flags:(Unix.([O_WRONLY; O_NONBLOCK; O_CREAT; O_TRUNC]))
      ~perm:0o600 ~mode:Lwt_io.Output (dir / fname)
      (fun oc ->
        Lwt_list.iter_s
          (fun v ->
            Lwt_io.write oc (what v) >>
              Lwt_io.write oc "\n") xs)
  in
  Lwt_unix.mkdir dir 0o700 >>
  (match pk_or_tp with
   | `PK pk -> create_file "public_keys.jsons" (string_of_trustee_public_key G.write) pk
   | `TP tp -> create_file "threshold.json" (string_of_threshold_parameters G.write) [tp]
  ) >>
  create_file "voters.txt" (fun x -> x.sv_id) se.se_voters >>
  create_file "metadata.json" string_of_metadata [metadata] >>
  create_file "election.json" (fun x -> x) [raw_election] >>
  (* construct Web_election instance *)
  let election = Election.of_string raw_election in
  let module W = (val Election.get_group election) in
  let module E = Election.Make (W) (LwtRandom) in
  let module B = Web_election.Make (E) in
  (* set up authentication *)
  let%lwt () =
    match metadata.e_auth_config with
    | None -> return ()
    | Some xs ->
       let auth_config =
         List.map (fun {auth_system; auth_instance; auth_config} ->
           auth_instance, (auth_system, List.map snd auth_config)
         ) xs
       in
       Web_persist.set_auth_config (Some uuid) auth_config
  in
  (* inject credentials *)
  let%lwt () =
    let fname = !spool_dir / uuid_s ^ ".public_creds.txt" in
    match%lwt read_file fname with
    | Some xs ->
       Lwt_list.iter_s B.inject_cred xs
       >> B.update_files ()
       >> Lwt_unix.unlink fname
    | None -> return_unit
  in
  (* create file with private keys, if any *)
  let%lwt () =
    match private_keys with
    | `None -> return_unit
    | `KEY x -> create_file "private_key.json" string_of_number [x]
    | `KEYS x -> create_file "private_keys.jsons" (fun x -> x) x
  in
  (* clean up setup database *)
  Ocsipersist.remove election_credtokens se.se_public_creds >>
  Lwt_list.iter_s
    (fun {st_token; _} ->
      if st_token <> "" then (
        Ocsipersist.remove election_pktokens st_token
      ) else return_unit
    )
    se.se_public_keys >>
  (match se.se_threshold_trustees with
   | None -> return_unit
   | Some ts ->
      Lwt_list.iter_s
        (fun x -> Ocsipersist.remove election_tpktokens x.stt_token)
        ts
  ) >>
  Ocsipersist.remove election_stable uuid_s >>
  (* inject passwords *)
  (match metadata.e_auth_config with
  | Some [{auth_system = "password"; _}] ->
     let table = "password_" ^ underscorize uuid in
     let table = Ocsipersist.open_table table in
     Lwt_list.iter_s
       (fun v ->
         let _, login = split_identity v.sv_id in
         match v.sv_password with
         | Some x -> Ocsipersist.add table login x
         | None -> return_unit
       ) se.se_voters >>
       dump_passwords (!spool_dir / uuid_s) table
  | _ -> return_unit) >>
  (* finish *)
  Web_persist.set_election_state uuid `Open >>
  Web_persist.set_election_date uuid (now ())

let cleanup_table ?uuid_s table =
  let table = Ocsipersist.open_table table in
  match uuid_s with
  | None ->
     let%lwt indexes = Ocsipersist.fold_step (fun k _ accu ->
       return (k :: accu)) table []
     in
     Lwt_list.iter_s (Ocsipersist.remove table) indexes
  | Some u -> Ocsipersist.remove table u

let cleanup_file f =
  try%lwt Lwt_unix.unlink f
  with _ -> return_unit

let archive_election uuid =
  let uuid_s = raw_string_of_uuid uuid in
  let uuid_u = underscorize uuid in
  let%lwt () = cleanup_table ~uuid_s "election_states" in
  let%lwt () = cleanup_table ~uuid_s "site_tokens_decrypt" in
  let%lwt () = cleanup_table ~uuid_s "election_pds" in
  let%lwt () = cleanup_table ~uuid_s "auth_configs" in
  let%lwt () = cleanup_table ("password_" ^ uuid_u) in
  let%lwt () = cleanup_table ("records_" ^ uuid_u) in
  let%lwt () = cleanup_table ("creds_" ^ uuid_u) in
  let%lwt () = cleanup_table ("ballots_" ^ uuid_u) in
  let%lwt () = cleanup_file (!spool_dir / uuid_s / "private_key.json") in
  let%lwt () = cleanup_file (!spool_dir / uuid_s / "private_keys.jsons") in
  return_unit

let () = Any.register ~service:home
  (fun () () ->
    Eliom_reference.unset Web_state.cont >>
    Redirection.send admin
  )

let get_finalized_elections_by_owner u =
  let%lwt elections, tallied, archived =
    Web_persist.get_elections_by_owner u >>=
    Lwt_list.fold_left_s (fun accu uuid ->
        let%lwt w = find_election uuid in
        let%lwt state = Web_persist.get_election_state uuid in
        let%lwt date = Web_persist.get_election_date uuid in
        let elections, tallied, archived = accu in
        match state with
        | `Tallied _ -> return (elections, (date, w) :: tallied, archived)
        | `Archived -> return (elections, tallied, (date, w) :: archived)
        | _ -> return ((date, w) :: elections, tallied, archived)
    ) ([], [], [])
  in
  let sort l =
    List.sort (fun (x, _) (y, _) -> datetime_compare x y) l |>
    List.map (fun (_, x) -> x)
  in
  return (sort elections, sort tallied, sort archived)

let with_site_user f =
  match%lwt Web_state.get_site_user () with
  | Some u -> f u
  | None -> forbidden ()

let () = Html5.register ~service:admin
  (fun () () ->
    let cont () = Redirection.send admin in
    Eliom_reference.set Web_state.cont [cont] >>
    let%lwt site_user = Web_state.get_site_user () in
    let%lwt elections =
      match site_user with
      | None -> return None
      | Some u ->
         let%lwt elections, tallied, archived = get_finalized_elections_by_owner u in
         let%lwt setup_elections =
           Ocsipersist.fold_step (fun k v accu ->
             let v = setup_election_of_string v in
             if v.se_owner = u then
               return ((uuid_of_raw_string k, v.se_questions.t_name) :: accu)
             else return accu
           ) election_stable []
         in
         return @@ Some (elections, tallied, archived, setup_elections)
    in
    T.admin ~elections ()
  )

let () = File.register ~service:source_code
  ~content_type:"application/x-gzip"
  (fun () () -> return !source_file)

let generate_uuid =
  let gen = Uuidm.v4_gen (Random.State.make_self_init ()) in
  fun () -> uuid_of_raw_string (Uuidm.to_string (gen ()))

let redir_preapply s u () = Redirection.send (preapply s u)

let create_new_election owner cred auth =
  let e_cred_authority = match cred with
    | `Automatic -> Some "server"
    | `Manual -> None
  in
  let e_auth_config = match auth with
    | `Password -> Some [{auth_system = "password"; auth_instance = "password"; auth_config = []}]
    | `Dummy -> Some [{auth_system = "dummy"; auth_instance = "dummy"; auth_config = []}]
    | `CAS server -> Some [{auth_system = "cas"; auth_instance = "cas"; auth_config = ["server", server]}]
  in
  let uuid = generate_uuid () in
  let uuid_s = raw_string_of_uuid uuid in
  let%lwt token = generate_token () in
  let se_metadata = {
    e_owner = Some owner;
    e_auth_config;
    e_cred_authority;
    e_trustees = None;
    e_languages = Some ["en"; "fr"];
  } in
  let question = {
    q_answers = [| "Answer 1"; "Answer 2"; "Blank" |];
    q_blank = None;
    q_min = 1;
    q_max = 1;
    q_question = "Question 1?";
  } in
  let se_questions = {
    t_description = "Description of the election.";
    t_name = "Name of the election";
    t_questions = [| question |];
  } in
  let se = {
    se_owner = owner;
    se_group = "{\"g\":\"2402352677501852209227687703532399932712287657378364916510075318787663274146353219320285676155269678799694668298749389095083896573425601900601068477164491735474137283104610458681314511781646755400527402889846139864532661215055797097162016168270312886432456663834863635782106154918419982534315189740658186868651151358576410138882215396016043228843603930989333662772848406593138406010231675095763777982665103606822406635076697764025346253773085133173495194248967754052573659049492477631475991575198775177711481490920456600205478127054728238140972518639858334115700568353695553423781475582491896050296680037745308460627\",\"p\":\"20694785691422546401013643657505008064922989295751104097100884787057374219242717401922237254497684338129066633138078958404960054389636289796393038773905722803605973749427671376777618898589872735865049081167099310535867780980030790491654063777173764198678527273474476341835600035698305193144284561701911000786737307333564123971732897913240474578834468260652327974647951137672658693582180046317922073668860052627186363386088796882120769432366149491002923444346373222145884100586421050242120365433561201320481118852408731077014151666200162313177169372189248078507711827842317498073276598828825169183103125680162072880719\",\"q\":\"78571733251071885079927659812671450121821421258408794611510081919805623223441\"}"; (* generated by fips.sage *)
    se_voters = [];
    se_questions;
    se_public_keys = [];
    se_metadata;
    se_public_creds = token;
    se_public_creds_received = false;
    se_threshold = None;
    se_threshold_trustees = None;
    se_threshold_parameters = None;
    se_threshold_error = None;
  } in
  let%lwt () = set_setup_election uuid se in
  let%lwt () = Ocsipersist.add election_credtokens token uuid_s in
  redir_preapply election_setup uuid ()

let () = Html5.register ~service:election_setup_pre
  (fun () () -> T.election_setup_pre ())

let () = Any.register ~service:election_setup_new
  (fun () (credmgmt, (auth, cas_server)) ->
    with_site_user (fun u ->
        let%lwt credmgmt = match credmgmt with
          | Some "auto" -> return `Automatic
          | Some "manual" -> return `Manual
          | _ -> fail_http 400
        in
        let%lwt auth = match auth with
          | Some "password" -> return `Password
          | Some "dummy" -> return `Dummy
          | Some "cas" -> return @@ `CAS cas_server
          | _ -> fail_http 400
        in
        create_new_election u credmgmt auth
      )
  )

let with_setup_election_ro uuid f =
  with_site_user (fun u ->
      let%lwt se = get_setup_election uuid in
      if se.se_owner = u then
        f se
      else forbidden ()
    )

let () =
  Html5.register ~service:election_setup
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          T.election_setup uuid se ()
        )
    )

let () =
  Any.register ~service:election_setup_trustees
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          match se.se_threshold_trustees with
          | None -> T.election_setup_trustees uuid se () >>= Html5.send
          | Some _ -> redir_preapply election_setup_threshold_trustees uuid ()
        )
    )

let () =
  Html5.register ~service:election_setup_threshold_trustees
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          T.election_setup_threshold_trustees uuid se ()
        )
    )

let () =
  Html5.register ~service:election_setup_credential_authority
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          T.election_setup_credential_authority uuid se ()
        )
    )

let election_setup_mutex = Lwt_mutex.create ()

let with_setup_election ?(save = true) uuid f =
  with_site_user (fun u ->
      Lwt_mutex.with_lock election_setup_mutex (fun () ->
          let%lwt se = get_setup_election uuid in
          if se.se_owner = u then (
            try%lwt
              let%lwt r = f se in
              let%lwt () = if save then set_setup_election uuid se else return_unit in
              return r
            with e ->
              let service = preapply election_setup uuid in
              T.generic_page ~title:"Error" ~service (Printexc.to_string e) () >>= Html5.send
          ) else forbidden ()
        )
    )

let () =
  Any.register ~service:election_setup_languages
    (fun uuid languages ->
      with_setup_election uuid (fun se ->
          let langs = languages_of_string languages in
          match langs with
          | [] ->
             let service = preapply election_setup uuid in
             T.generic_page ~title:"Error" ~service
               "You must select at least one language!" () >>= Html5.send
          | _ :: _ ->
             let unavailable =
               List.filter (fun x ->
                   not (List.mem x available_languages)
                 ) langs
             in
             match unavailable with
             | [] ->
                se.se_metadata <- {
                   se.se_metadata with
                   e_languages = Some langs
                 };
                redir_preapply election_setup uuid ()
             | l :: _ ->
                let service = preapply election_setup uuid in
                T.generic_page ~title:"Error" ~service
                  ("No such language: " ^ l) () >>= Html5.send
        )
    )

let () =
  Any.register ~service:election_setup_description
    (fun uuid (name, description) ->
      with_setup_election uuid (fun se ->
          se.se_questions <- {se.se_questions with
                               t_name = name;
                               t_description = description;
                             };
          redir_preapply election_setup uuid ()
        )
    )

let generate_password langs title url id =
  let email, login = split_identity id in
  let%lwt salt = generate_token () in
  let%lwt password = generate_token () in
  let hashed = sha256_hex (salt ^ password) in
  let bodies = List.map (fun lang ->
    let module L = (val Web_i18n.get_lang lang) in
    Printf.sprintf L.mail_password title login password url
  ) langs in
  let body = PString.concat "\n\n----------\n\n" bodies in
  let body = body ^ "\n\n-- \nBelenios" in
  let subject =
    let lang = List.hd langs in
    let module L = (val Web_i18n.get_lang lang) in
    Printf.sprintf L.mail_password_subject title
  in
  send_email email subject body >>
  return (salt, hashed)

let handle_password se uuid ~force voters =
  if List.length voters > !maxmailsatonce then
    Lwt.fail (Failure (Printf.sprintf "Cannot send passwords, there are too many voters (max is %d)" !maxmailsatonce))
  else
  let title = se.se_questions.t_name in
  let url = Eliom_uri.make_string_uri ~absolute:true ~service:election_home
    (uuid, ()) |> rewrite_prefix
  in
  let langs = get_languages se.se_metadata.e_languages in
  let%lwt () =
    Lwt_list.iter_s (fun id ->
        match id.sv_password with
        | Some _ when not force -> return_unit
        | None | Some _ ->
           let%lwt x = generate_password langs title url id.sv_id in
           return (id.sv_password <- Some x)
      ) voters
  in
  let service = preapply election_setup uuid in
  T.generic_page ~title:"Success" ~service
    "Passwords have been generated and mailed!" () >>= Html5.send

let () =
  Any.register ~service:election_setup_auth_genpwd
    (fun uuid () ->
      with_setup_election uuid (fun se ->
          handle_password se uuid ~force:false se.se_voters
        )
    )

let () =
  Any.register ~service:election_regenpwd
    (fun (uuid, ()) () ->
      T.regenpwd uuid () >>= Html5.send)

let () =
  Any.register ~service:election_regenpwd_post
    (fun (uuid, ()) user ->
      with_site_user (fun u ->
          let%lwt election = find_election uuid in
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          if metadata.e_owner = Some u then (
            let table = "password_" ^ underscorize uuid in
            let table = Ocsipersist.open_table table in
            let title = election.e_params.e_name in
            let url = Eliom_uri.make_string_uri
                        ~absolute:true ~service:election_home
                        (uuid, ()) |> rewrite_prefix
            in
            let service = preapply election_admin (uuid, ()) in
            (try%lwt
               let%lwt _ = Ocsipersist.find table user in
               let langs = get_languages metadata.e_languages in
               let%lwt x = generate_password langs title url user in
               Ocsipersist.add table user x >>
                 dump_passwords (!spool_dir / raw_string_of_uuid uuid) table >>
                 T.generic_page ~title:"Success" ~service
                   ("A new password has been mailed to " ^ user ^ ".") ()
               >>= Html5.send
              with Not_found ->
                T.generic_page ~title:"Error" ~service
                  (user ^ " is not a registered user for this election.") ()
                >>= Html5.send
            )
          ) else forbidden ()
        )
    )

let () =
  Html5.register ~service:election_setup_questions
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          T.election_setup_questions uuid se ()
        )
    )

let () =
  Any.register ~service:election_setup_questions_post
    (fun uuid template ->
      with_setup_election uuid (fun se ->
          se.se_questions <- template_of_string template;
          redir_preapply election_setup uuid ()
        )
    )

let () =
  Html5.register ~service:election_setup_voters
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          T.election_setup_voters uuid se !maxmailsatonce ()
        )
    )

(* see http://www.regular-expressions.info/email.html *)
let identity_rex = Pcre.regexp
  ~flags:[`CASELESS]
  "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,7}(,[A-Z0-9._%+-]+)?$"

let is_identity x =
  try ignore (Pcre.pcre_exec ~rex:identity_rex x); true
  with Not_found -> false

let merge_voters a b f =
  let existing = List.fold_left (fun accu sv ->
    SSet.add sv.sv_id accu
  ) SSet.empty a in
  let _, res = List.fold_left (fun (existing, accu) sv_id ->
    if SSet.mem sv_id existing then
      (existing, accu)
    else
      (SSet.add sv_id existing, {sv_id; sv_password = f sv_id} :: accu)
  ) (existing, List.rev a) b in
  List.rev res

let () =
  Any.register ~service:election_setup_voters_add
    (fun uuid voters ->
      with_setup_election uuid (fun se ->
          if se.se_public_creds_received then
            forbidden ()
          else (
            let voters = Pcre.split voters in
            let () =
              try
                let bad = List.find (fun x -> not (is_identity x)) voters in
                Printf.ksprintf failwith "%S is not a valid identity" bad
              with Not_found -> ()
            in
            se.se_voters <- merge_voters se.se_voters voters (fun _ -> None);
            redir_preapply election_setup_voters uuid ()
          )
        )
    )

let () =
  Any.register ~service:election_setup_voters_remove
    (fun uuid voter ->
      with_setup_election uuid (fun se ->
          if se.se_public_creds_received then
            forbidden ()
          else (
            se.se_voters <- List.filter (fun v -> v.sv_id <> voter) se.se_voters;
            redir_preapply election_setup_voters uuid ()
          )
        )
    )

let () =
  Any.register ~service:election_setup_voters_passwd
    (fun uuid voter ->
      with_setup_election uuid (fun se ->
          let voter = List.filter (fun v -> v.sv_id = voter) se.se_voters in
          handle_password se uuid ~force:true voter
        )
    )

let () =
  Any.register ~service:election_setup_trustee_add
    (fun uuid st_id ->
      with_setup_election uuid (fun se ->
          if is_email st_id then (
            let%lwt st_token = generate_token () in
            let trustee = {st_id; st_token; st_public_key = ""; st_private_key = None} in
            se.se_public_keys <- se.se_public_keys @ [trustee];
            let%lwt () = Ocsipersist.add election_pktokens st_token (raw_string_of_uuid uuid) in
            redir_preapply election_setup_trustees uuid ()
          ) else (
            let msg = st_id ^ " is not a valid e-mail address!" in
            let service = preapply election_setup_trustees uuid in
            T.generic_page ~title:"Error" ~service msg () >>= Html5.send
          )
        )
    )

let () =
  Any.register ~service:election_setup_trustee_add_server
    (fun uuid () ->
      with_setup_election uuid (fun se ->
          let st_id = "server" and st_token = "" in
          let module G = (val Group.of_string se.se_group) in
          let module K = Trustees.MakeSimple (G) (LwtRandom) in
          let%lwt private_key = K.generate () in
          let%lwt public_key = K.prove private_key in
          let st_public_key = string_of_trustee_public_key G.write public_key in
          let st_private_key = Some private_key in
          let trustee = {st_id; st_token; st_public_key; st_private_key} in
          se.se_public_keys <- se.se_public_keys @ [trustee];
          redir_preapply election_setup_trustees uuid ()
        )
    )

let () =
  Any.register ~service:election_setup_trustee_del
    (fun uuid index ->
      with_setup_election uuid (fun se ->
          let trustees, old =
            se.se_public_keys |>
              List.mapi (fun i x -> i, x) |>
              List.partition (fun (i, _) -> i <> index) |>
              (fun (x, y) -> List.map snd x, List.map snd y)
          in
          se.se_public_keys <- trustees;
          let%lwt () =
            Lwt_list.iter_s (fun {st_token; _} ->
                if st_token <> "" then (
                  Ocsipersist.remove election_pktokens st_token
                ) else return_unit
              ) old
          in
          redir_preapply election_setup_trustees uuid ()
        )
    )

let () =
  Html5.register ~service:election_setup_credentials
    (fun token () ->
     let%lwt uuid = Ocsipersist.find election_credtokens token in
     let uuid = uuid_of_raw_string uuid in
     let%lwt se = get_setup_election uuid in
     T.election_setup_credentials token uuid se ()
    )

let wrap_handler f =
  try%lwt f ()
  with
  | e -> T.generic_page ~title:"Error" (Printexc.to_string e) () >>= Html5.send

let handle_credentials_post token creds =
  let%lwt uuid = Ocsipersist.find election_credtokens token in
  let uuid = uuid_of_raw_string uuid in
  let%lwt se = get_setup_election uuid in
  if se.se_public_creds_received then forbidden () else
  let module G = (val Group.of_string se.se_group : GROUP) in
  let fname = !spool_dir / raw_string_of_uuid uuid ^ ".public_creds.txt" in
  Lwt_mutex.with_lock
    election_setup_mutex
    (fun () ->
     Lwt_io.with_file
       ~flags:(Unix.([O_WRONLY; O_NONBLOCK; O_CREAT; O_TRUNC]))
       ~perm:0o600 ~mode:Lwt_io.Output fname
       (fun oc -> Lwt_io.write_chars oc creds)
    ) >>
  let%lwt () =
    let i = ref 1 in
    match%lwt read_file fname with
    | Some xs ->
       return (
           List.iter (fun x ->
               try
                 let x = G.of_string x in
                 if not (G.check x) then raise Exit;
                 incr i
               with _ ->
                 Printf.ksprintf failwith "invalid credential at line %d" !i
             ) xs
         )
    | None -> return_unit
  in
  let () = se.se_metadata <- {se.se_metadata with e_cred_authority = None} in
  let () = se.se_public_creds_received <- true in
  set_setup_election uuid se >>
  T.generic_page ~title:"Success"
    "Credentials have been received and checked!" () >>= Html5.send

let () =
  Any.register ~service:election_setup_credentials_post
    (fun token creds ->
     let s = Lwt_stream.of_string creds in
     wrap_handler (fun () -> handle_credentials_post token s))

let () =
  Any.register ~service:election_setup_credentials_post_file
    (fun token creds ->
     let s = Lwt_io.chars_of_file creds.Ocsigen_extensions.tmp_filename in
     wrap_handler (fun () -> handle_credentials_post token s))

module CG = Credential.MakeGenerate (LwtRandom)

let () =
  Any.register ~service:election_setup_credentials_server
    (fun uuid () ->
      with_setup_election uuid (fun se ->
          let nvoters = List.length se.se_voters in
          if nvoters > !maxmailsatonce then
            Lwt.fail (Failure (Printf.sprintf "Cannot send credentials, there are too many voters (max is %d)" !maxmailsatonce))
          else if nvoters = 0 then
            Lwt.fail (Failure "No voters")
          else if se.se_public_creds_received then
            forbidden ()
          else (
            let () = se.se_metadata <- {se.se_metadata with
                                         e_cred_authority = Some "server"
                                       } in
            let title = se.se_questions.t_name in
            let url = Eliom_uri.make_string_uri
                        ~absolute:true ~service:election_home
                        (uuid, ()) |> rewrite_prefix
            in
            let module G = (val Group.of_string se.se_group : GROUP) in
            let module CD = Credential.MakeDerive (G) in
            let%lwt creds =
              Lwt_list.fold_left_s (fun accu v ->
                  let email, login = split_identity v.sv_id in
                  let%lwt cred = CG.generate () in
                  let pub_cred =
                    let x = CD.derive uuid cred in
                    let y = G.(g **~ x) in
                    G.to_string y
                  in
                  let langs = get_languages se.se_metadata.e_languages in
                  let bodies = List.map (fun lang ->
                                   let module L = (val Web_i18n.get_lang lang) in
                                   Printf.sprintf L.mail_credential title login cred url
                                 ) langs in
                  let body = PString.concat "\n\n----------\n\n" bodies in
                  let body = body ^ "\n\n-- \nBelenios" in
                  let subject =
                    let lang = List.hd langs in
                    let module L = (val Web_i18n.get_lang lang) in
                    Printf.sprintf L.mail_credential_subject title
                  in
                  let%lwt () = send_email email subject body in
                  return @@ SSet.add pub_cred accu
                ) SSet.empty se.se_voters
            in
            let creds = SSet.elements creds in
            let fname = !spool_dir / raw_string_of_uuid uuid ^ ".public_creds.txt" in
            let%lwt () =
              Lwt_io.with_file
                ~flags:(Unix.([O_WRONLY; O_NONBLOCK; O_CREAT; O_TRUNC]))
                ~perm:0o600 ~mode:Lwt_io.Output fname
                (fun oc ->
                  Lwt_list.iter_s (Lwt_io.write_line oc) creds)
            in
            se.se_public_creds_received <- true;
            let service = preapply election_setup uuid in
            T.generic_page ~title:"Success" ~service
              "Credentials have been generated and mailed!" () >>= Html5.send
          )
        )
    )

let () =
  Html5.register ~service:election_setup_trustee
    (fun token () ->
     let%lwt uuid = Ocsipersist.find election_pktokens token in
     let uuid = uuid_of_raw_string uuid in
     let%lwt se = get_setup_election uuid in
     T.election_setup_trustee token uuid se ()
    )

let () =
  Any.register ~service:election_setup_trustee_post
    (fun token public_key ->
     wrap_handler
       (fun () ->
        let%lwt uuid = Ocsipersist.find election_pktokens token in
        let uuid = uuid_of_raw_string uuid in
        Lwt_mutex.with_lock
          election_setup_mutex
          (fun () ->
           let%lwt se = get_setup_election uuid in
           let t = List.find (fun x -> token = x.st_token) se.se_public_keys in
           let module G = (val Group.of_string se.se_group : GROUP) in
           let pk = trustee_public_key_of_string G.read public_key in
           let module KG = Trustees.MakeSimple (G) (LwtRandom) in
           if not (KG.check pk) then failwith "invalid public key";
           (* we keep pk as a string because of G.t *)
           t.st_public_key <- public_key;
           set_setup_election uuid se
          ) >> T.generic_page ~title:"Success"
            "Your key has been received and checked!"
            () >>= Html5.send
       )
    )

let () =
  Any.register ~service:election_setup_confirm
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          T.election_setup_confirm uuid se () >>= Html5.send
        )
    )

let () =
  Any.register ~service:election_setup_create
    (fun uuid () ->
      with_setup_election ~save:false uuid (fun se ->
          try%lwt
            let%lwt () = finalize_election uuid se in
            redir_preapply election_admin (uuid, ()) ()
          with e ->
            T.new_election_failure (`Exception e) () >>= Html5.send
        )
    )

let () =
  Any.register ~service:election_setup_destroy
    (fun uuid () ->
      with_setup_election ~save:false uuid (fun se ->
          let uuid_s = raw_string_of_uuid uuid in
          (* clean up credentials *)
          let%lwt () =
            let fname = !spool_dir / uuid_s ^ ".public_creds.txt" in
            try%lwt Lwt_unix.unlink fname
            with _ -> return_unit
          in
          (* clean up setup database *)
          let%lwt () = Ocsipersist.remove election_credtokens se.se_public_creds in
          let%lwt () =
            Lwt_list.iter_s (fun {st_token; _} ->
                if st_token <> "" then
                  Ocsipersist.remove election_pktokens st_token
                else return_unit
              ) se.se_public_keys
          in
          let%lwt () = match se.se_threshold_trustees with
            | None -> return_unit
            | Some ts ->
               Lwt_list.iter_s (fun {stt_token; _} ->
                   Ocsipersist.remove election_tpktokens stt_token
                 ) ts
          in
          let%lwt () = Ocsipersist.remove election_stable uuid_s in
          Redirection.send admin
        )
    )

let () =
  Html5.register ~service:election_setup_import
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          let%lwt elections = get_finalized_elections_by_owner se.se_owner in
          T.election_setup_import uuid se elections ()
        )
    )

let () =
  Any.register ~service:election_setup_import_post
    (fun uuid from ->
      with_setup_election uuid (fun se ->
          let from_s = raw_string_of_uuid from in
          let%lwt voters = Web_persist.get_voters from in
          let%lwt passwords = Web_persist.get_passwords from in
          let get_password =
            match passwords with
            | None -> fun _ -> None
            | Some p -> fun sv_id ->
                        let _, login = split_identity sv_id in
                        try Some (SMap.find login p)
                        with Not_found -> None
          in
          match voters with
          | Some voters ->
             if se.se_public_creds_received then
               forbidden ()
             else (
               se.se_voters <- merge_voters se.se_voters voters get_password;
               redir_preapply election_setup_voters uuid ()
             )
          | None ->
             T.generic_page ~title:"Error"
               ~service:(preapply election_setup_voters uuid)
               (Printf.sprintf
                  "Could not retrieve voter list from election %s"
                  from_s)
               () >>= Html5.send
        )
    )

let () =
  Html5.register ~service:election_setup_import_trustees
    (fun uuid () ->
      with_setup_election_ro uuid (fun se ->
          let%lwt elections = get_finalized_elections_by_owner se.se_owner in
          T.election_setup_import_trustees uuid se elections ()
        )
    )

exception TrusteeImportError of string

let () =
  Any.register ~service:election_setup_import_trustees_post
    (fun uuid from ->
      with_setup_election uuid (fun se ->
          let uuid_s = raw_string_of_uuid uuid in
          let%lwt metadata = Web_persist.get_election_metadata from in
          let%lwt threshold = Web_persist.get_threshold from in
          let%lwt public_keys = Web_persist.get_public_keys from in
          try%lwt
               match metadata.e_trustees, threshold, public_keys with
               | Some ts, Some raw_tp, None ->
                  if se.se_threshold_trustees <> None then
                    raise (TrusteeImportError "Importing threshold trustees after having already added ones is not supported");
                  let module G = (val Group.of_string se.se_group : GROUP) in
                  let module P = Trustees.MakePKI (G) (LwtRandom) in
                  let module C = Trustees.MakeChannels (G) (LwtRandom) (P) in
                  let module K = Trustees.MakePedersen (G) (LwtRandom) (P) (C) in
                  let tp = threshold_parameters_of_string G.read raw_tp in
                  if not (K.check tp) then
                    raise (TrusteeImportError "Imported threshold trustees are invalid for this election!");
                  let%lwt privs = Web_persist.get_private_keys from in
                  let%lwt se_threshold_trustees =
                    match privs with
                    | Some privs ->
                       let rec loop ts pubs privs accu =
                         match ts, pubs, privs with
                         | stt_id :: ts, vo_public_key :: pubs, vo_private_key :: privs ->
                            let%lwt stt_token = generate_token () in
                            let stt_voutput = {vo_public_key; vo_private_key} in
                            let stt_voutput = Some (string_of_voutput G.write stt_voutput) in
                            let stt = {
                                stt_id; stt_token; stt_voutput;
                                stt_step = Some 7; stt_cert = None;
                                stt_polynomial = None; stt_vinput = None;
                              } in
                            loop ts pubs privs (stt :: accu)
                         | [], [], [] -> return (List.rev accu)
                         | _, _, _ -> raise (TrusteeImportError "Inconsistency in imported election!")
                       in loop ts (Array.to_list tp.t_verification_keys) privs []
                    | None -> raise (TrusteeImportError "Encrypted decryption keys are missing!")
                  in
                  se.se_threshold <- Some tp.t_threshold;
                  se.se_threshold_trustees <- Some se_threshold_trustees;
                  se.se_threshold_parameters <- Some raw_tp;
                  Lwt_list.iter_s (fun {stt_token; _} ->
                      Ocsipersist.add election_tpktokens stt_token uuid_s
                    ) se_threshold_trustees >>
                  redir_preapply election_setup_threshold_trustees uuid ()
               | Some ts, None, Some pks when List.length ts = List.length pks ->
                  let module G = (val Group.of_string se.se_group) in
                  let module KG = Trustees.MakeSimple (G) (LwtRandom) in
                  let%lwt trustees =
                    List.combine ts pks
                    |> Lwt_list.map_p
                         (fun (st_id, st_public_key) ->
                           let%lwt st_token, st_private_key, st_public_key =
                             if st_id = "server" then (
                               let%lwt private_key = KG.generate () in
                               let%lwt public_key = KG.prove private_key in
                               let public_key = string_of_trustee_public_key G.write public_key in
                               return ("", Some private_key, public_key)
                             ) else (
                               let%lwt st_token = generate_token () in
                               return (st_token, None, st_public_key)
                             )
                           in
                           return {st_id; st_token; st_public_key; st_private_key})
                  in
                  let () =
                    (* check that imported keys are valid *)
                    if not @@ List.for_all (fun t ->
                                  let pk = t.st_public_key in
                                  let pk = trustee_public_key_of_string G.read pk in
                                  KG.check pk) trustees then
                      raise (TrusteeImportError "Imported keys are invalid for this election!")
                  in
                  se.se_public_keys <- se.se_public_keys @ trustees;
                  Lwt_list.iter_s (fun {st_token; _} ->
                      if st_token <> "" then (
                        Ocsipersist.add election_pktokens st_token uuid_s
                      ) else return_unit
                    ) trustees >>
                  redir_preapply election_setup_trustees uuid ()
               | _, _, _ ->
                  [%lwt raise (TrusteeImportError "Could not retrieve trustees from selected election!")]
          with
          | TrusteeImportError msg ->
             T.generic_page ~title:"Error"
               ~service:(preapply election_setup_trustees uuid)
               msg () >>= Html5.send
        )
    )

let () =
  Any.register ~service:election_home
    (fun (uuid, ()) () ->
      try%lwt
        let%lwt w = find_election uuid in
        Eliom_reference.unset Web_state.ballot >>
        let cont = redir_preapply election_home (uuid, ()) in
        Eliom_reference.set Web_state.cont [cont] >>
        match%lwt Eliom_reference.get Web_state.cast_confirmed with
        | Some result ->
           Eliom_reference.unset Web_state.cast_confirmed >>
           Eliom_reference.unset Web_state.user >>
           T.cast_confirmed w ~result () >>= Html5.send
        | None ->
           let%lwt state = Web_persist.get_election_state uuid in
           T.election_home w state () >>= Html5.send
      with Not_found ->
        let%lwt lang = Eliom_reference.get Web_state.language in
        let module L = (val Web_i18n.get_lang lang) in
        T.generic_page ~title:L.not_yet_open
          ~service:(preapply election_home (uuid, ()))
          L.come_back_later ()
          >>= Html5.send)

let () =
  Any.register ~service:set_cookie_disclaimer
    (fun () () ->
      Eliom_reference.set Web_state.show_cookie_disclaimer false >>
      let%lwt cont = Web_state.cont_pop () in
      match cont with
      | Some f -> f ()
      | None ->
         let%lwt lang = Eliom_reference.get Web_state.language in
         let module L = (val Web_i18n.get_lang lang) in
         T.generic_page ~title:L.cookies_are_blocked
           L.please_enable_them ()
           >>= Html5.send)

let () =
  Any.register ~service:election_admin
    (fun (uuid, ()) () ->
     let uuid_s = raw_string_of_uuid uuid in
     let%lwt w = find_election uuid in
     let%lwt metadata = Web_persist.get_election_metadata uuid in
     let%lwt site_user = Web_state.get_site_user () in
     match site_user with
     | Some u when metadata.e_owner = Some u ->
        let%lwt state = Web_persist.get_election_state uuid in
        let get_tokens_decrypt () =
          try%lwt
            Ocsipersist.find election_tokens_decrypt uuid_s
          with Not_found ->
            match metadata.e_trustees with
            | None -> failwith "missing trustees in get_tokens_decrypt"
            | Some ts ->
               let%lwt ts = Lwt_list.map_s (fun _ -> generate_token ()) ts in
               Ocsipersist.add election_tokens_decrypt uuid_s ts >>
               return ts
        in
        T.election_admin w metadata state get_tokens_decrypt () >>= Html5.send
     | _ ->
        let cont = redir_preapply election_admin (uuid, ()) in
        Eliom_reference.set Web_state.cont [cont] >>
        redir_preapply site_login None ()
    )

let election_set_state state (uuid, ()) () =
  with_site_user (fun u ->
      let%lwt metadata = Web_persist.get_election_metadata uuid in
      if metadata.e_owner = Some u then (
        let%lwt () =
          match%lwt Web_persist.get_election_state uuid with
          | `Open | `Closed -> return ()
          | _ -> forbidden ()
        in
        let state = if state then `Open else `Closed in
        Web_persist.set_election_state uuid state >>
          redir_preapply election_admin (uuid, ()) ()
      ) else forbidden ()
    )

let () = Any.register ~service:election_open (election_set_state true)
let () = Any.register ~service:election_close (election_set_state false)

let () =
  Any.register ~service:election_archive
    (fun (uuid, ()) () ->
      with_site_user (fun u ->
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          if metadata.e_owner = Some u then (
            archive_election uuid >>
              redir_preapply election_admin (uuid, ()) ()
          ) else forbidden ()
        )
    )

let () =
  Any.register ~service:election_update_credential
    (fun (uuid, ()) () ->
      with_site_user (fun u ->
          let%lwt w = find_election uuid in
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          if metadata.e_owner = Some u then (
            T.update_credential w () >>= Html5.send
          ) else forbidden ()
        )
    )

let () =
  Any.register ~service:election_update_credential_post
    (fun (uuid, ()) (old, new_) ->
      with_site_user (fun u ->
          let%lwt election = find_election uuid in
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          let module W = (val Election.get_group election) in
          let module E = Election.Make (W) (LwtRandom) in
          let module B = Web_election.Make (E) in
          if metadata.e_owner = Some u then (
            try%lwt
                  B.update_cred ~old ~new_ >>
                  String.send ("OK", "text/plain")
            with Error e ->
               String.send ("Error: " ^ explain_error e, "text/plain")
          ) else forbidden ()
        )
    )

let () =
  Any.register ~service:election_vote
    (fun (uuid, ()) () ->
      Eliom_reference.unset Web_state.ballot >>
      Web_templates.booth uuid >>= Html5.send)

let () =
  Any.register ~service:election_cast
    (fun (uuid, ()) () ->
      let%lwt w = find_election uuid in
      let cont = redir_preapply election_cast (uuid, ()) in
      Eliom_reference.set Web_state.cont [cont] >>
      match%lwt Eliom_reference.get Web_state.ballot with
      | Some b -> T.cast_confirmation w (sha256_b64 b) () >>= Html5.send
      | None -> T.cast_raw w () >>= Html5.send)

let () =
  Any.register ~service:election_cast_post
    (fun (uuid, ()) (ballot_raw, ballot_file) ->
      let%lwt user = Web_state.get_election_user uuid in
      let%lwt the_ballot = match ballot_raw, ballot_file with
        | Some ballot, None -> return ballot
        | None, Some fi ->
           let fname = fi.Ocsigen_extensions.tmp_filename in
           Lwt_stream.to_string (Lwt_io.chars_of_file fname)
        | _, _ -> fail_http 400
      in
      let the_ballot = PString.trim the_ballot in
      let cont = redir_preapply election_cast (uuid, ()) in
      Eliom_reference.set Web_state.cont [cont] >>
      Eliom_reference.set Web_state.ballot (Some the_ballot) >>
      match user with
      | None -> redir_preapply election_login ((uuid, ()), None) ()
      | Some _ -> cont ())

let () =
  Any.register ~service:election_cast_confirm
    (fun (uuid, ()) () ->
      let%lwt election = find_election uuid in
      let module W = (val Election.get_group election) in
      let module E = Election.Make (W) (LwtRandom) in
      let module B = Web_election.Make (E) in
      match%lwt Eliom_reference.get Web_state.ballot with
      | Some the_ballot ->
         begin
           Eliom_reference.unset Web_state.ballot >>
           match%lwt Web_state.get_election_user uuid with
           | Some u ->
              let record = u, now () in
              let%lwt result =
                try%lwt
                  let%lwt hash = B.cast the_ballot record in
                  return (`Valid hash)
                with Error e -> return (`Error e)
              in
              Eliom_reference.set Web_state.cast_confirmed (Some result) >>
              redir_preapply election_home (uuid, ()) ()
           | None -> forbidden ()
         end
      | None -> fail_http 404)

let () =
  Any.register ~service:election_pretty_ballots
    (fun (uuid, ()) () ->
      let%lwt w = find_election uuid in
      let%lwt ballots = Web_persist.get_ballot_hashes uuid in
      let%lwt result = Web_persist.get_election_result uuid in
      T.pretty_ballots w ballots result () >>= Html5.send)

let () =
  Any.register ~service:election_pretty_ballot
    (fun ((uuid, ()), hash) () ->
      let%lwt ballot = Web_persist.get_ballot_by_hash uuid hash in
      match ballot with
      | None -> fail_http 404
      | Some b ->
         String.send (b, "application/json") >>=
           (fun x -> return @@ cast_unknown_content_kind x))

let () =
  let rex = Pcre.regexp "\".*\" \".*:(.*)\"" in
  Any.register ~service:election_missing_voters
    (fun (uuid, ()) () ->
      with_site_user (fun u ->
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          if metadata.e_owner = Some u then (
            let%lwt voters =
              match%lwt read_file ~uuid (string_of_election_file ESVoters) with
              | Some vs ->
                 return (
                     List.fold_left (fun accu v ->
                         let _, login = split_identity v in
                         SSet.add login accu
                       ) SSet.empty vs
                   )
              | None -> return SSet.empty
            in
            let%lwt voters =
              match%lwt read_file ~uuid (string_of_election_file ESRecords) with
              | Some rs ->
                 return (
                     List.fold_left (fun accu r ->
                         let s = Pcre.exec ~rex r in
                         let v = Pcre.get_substring s 1 in
                         SSet.remove v accu
                       ) voters rs
                   )
              | None -> return voters
            in
            let buf = Buffer.create 128 in
            SSet.iter (fun v ->
                Buffer.add_string buf v;
                Buffer.add_char buf '\n'
              ) voters;
            String.send (Buffer.contents buf, "text/plain")
          ) else forbidden ()
        )
    )

let () =
  let rex = Pcre.regexp "\"(.*)\\..*\" \".*:(.*)\"" in
  Any.register ~service:election_pretty_records
    (fun (uuid, ()) () ->
      with_site_user (fun u ->
          let%lwt w = find_election uuid in
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          if metadata.e_owner = Some u then (
            let%lwt records =
              match%lwt read_file ~uuid (string_of_election_file ESRecords) with
              | Some rs ->
                 return (
                     List.rev_map (fun r ->
                         let s = Pcre.exec ~rex r in
                         let date = Pcre.get_substring s 1 in
                         let voter = Pcre.get_substring s 2 in
                         (date, voter)
                       ) rs
                   )
              | None -> return []
            in
            T.pretty_records w (List.rev records) () >>= Html5.send
          ) else forbidden ()
        )
    )

let find_trustee_id uuid token =
  try%lwt
    let%lwt tokens = Ocsipersist.find election_tokens_decrypt (raw_string_of_uuid uuid) in
    let rec find i = function
      | [] -> raise Not_found
      | t :: ts -> if t = token then i else find (i+1) ts
    in
    return (find 1 tokens)
  with Not_found -> return (try int_of_string token with _ -> 0)

let () =
  Any.register ~service:election_tally_trustees
    (fun (uuid, ((), token)) () ->
      let%lwt w = find_election uuid in
      let%lwt () =
        match%lwt Web_persist.get_election_state uuid with
        | `EncryptedTally _ -> return ()
        | _ -> fail_http 404
      in
      let%lwt trustee_id = find_trustee_id uuid token in
      let%lwt pds = Web_persist.get_partial_decryptions uuid in
      if List.mem_assoc trustee_id pds then (
        T.generic_page ~title:"Error"
          "Your partial decryption has already been received and checked!"
          () >>= Html5.send
      ) else (
        T.tally_trustees w trustee_id token () >>= Html5.send
      ))

let () =
  Any.register ~service:election_tally_trustees_post
    (fun (uuid, ((), token)) partial_decryption ->
      let%lwt () =
        match%lwt Web_persist.get_election_state uuid with
        | `EncryptedTally _ -> return ()
        | _ -> forbidden ()
      in
      let%lwt trustee_id = find_trustee_id uuid token in
      let%lwt pds = Web_persist.get_partial_decryptions uuid in
      let%lwt () =
        if List.mem_assoc trustee_id pds then forbidden () else return ()
      in
      let%lwt () =
        if trustee_id > 0 then return () else fail_http 404
      in
      let%lwt election = find_election uuid in
      let module W = (val Election.get_group election) in
      let module E = Election.Make (W) (LwtRandom) in
      let%lwt pks =
        match%lwt Web_persist.get_threshold uuid with
        | Some tp ->
           let tp = threshold_parameters_of_string W.G.read tp in
           return tp.t_verification_keys
        | None ->
           match%lwt Web_persist.get_public_keys uuid with
           | None -> failwith "no public keys in election_tally_trustees_post"
           | Some pks ->
              let pks = Array.of_list pks in
              let pks = Array.map (trustee_public_key_of_string W.G.read) pks in
              return pks
      in
      let pk = pks.(trustee_id-1).trustee_public_key in
      let pd = partial_decryption_of_string W.G.read partial_decryption in
      let et = !spool_dir / raw_string_of_uuid uuid / string_of_election_file ESETally in
      let%lwt et = Lwt_io.chars_of_file et |> Lwt_stream.to_string in
      let et = encrypted_tally_of_string W.G.read et in
      if E.check_factor et pk pd then (
        let pds = (trustee_id, partial_decryption) :: pds in
        let%lwt () = Web_persist.set_partial_decryptions uuid pds in
        T.generic_page ~title:"Success"
          "Your partial decryption has been received and checked!" () >>=
        Html5.send
      ) else (
        let service = preapply election_tally_trustees (uuid, ((), token)) in
        T.generic_page ~title:"Error" ~service
          "The partial decryption didn't pass validation!" () >>=
        Html5.send
      ))

let handle_election_tally_release (uuid, ()) () =
  with_site_user (fun u ->
      let uuid_s = raw_string_of_uuid uuid in
      let%lwt election = find_election uuid in
      let%lwt metadata = Web_persist.get_election_metadata uuid in
      let module W = (val Election.get_group election) in
      let module E = Election.Make (W) (LwtRandom) in
      if metadata.e_owner = Some u then (
        let%lwt npks, ntallied =
          match%lwt Web_persist.get_election_state uuid with
          | `EncryptedTally (npks, ntallied, _) -> return (npks, ntallied)
          | _ -> forbidden ()
        in
        let%lwt et =
          !spool_dir / uuid_s / string_of_election_file ESETally |>
            Lwt_io.chars_of_file |> Lwt_stream.to_string >>=
            wrap1 (encrypted_tally_of_string W.G.read)
        in
        let%lwt tp = Web_persist.get_threshold uuid in
        let tp =
          match tp with
          | None -> None
          | Some tp -> Some (threshold_parameters_of_string W.G.read tp)
        in
        let threshold =
          match tp with
          | None -> npks
          | Some tp -> tp.t_threshold
        in
        let%lwt pds = Web_persist.get_partial_decryptions uuid in
        let pds = List.map snd pds in
        let pds = List.map (partial_decryption_of_string W.G.read) pds in
        let%lwt () =
          if List.length pds < threshold then fail_http 404 else return_unit
        in
        let checker = E.check_factor et in
        let%lwt combinator =
          match tp with
          | None ->
             let module K = Trustees.MakeSimple (W.G) (LwtRandom) in
             let%lwt pks =
               match%lwt Web_persist.get_public_keys uuid with
               | Some l -> return (Array.of_list l)
               | _ -> fail_http 404
             in
             let pks =
               Array.map (fun pk ->
                   (trustee_public_key_of_string W.G.read pk).trustee_public_key
                 ) pks
             in
             return (K.combine_factors checker pks)
          | Some tp ->
             let module P = Trustees.MakePKI (W.G) (LwtRandom) in
             let module C = Trustees.MakeChannels (W.G) (LwtRandom) (P) in
             let module K = Trustees.MakePedersen (W.G) (LwtRandom) (P) (C) in
             return (K.combine_factors checker tp)
        in
        let result = E.compute_result ntallied et pds combinator in
        let%lwt () =
          let result = string_of_result W.G.write result in
          write_file ~uuid (string_of_election_file ESResult) [result]
        in
        let%lwt () = Web_persist.set_election_state uuid (`Tallied result.result) in
        let%lwt () = Ocsipersist.remove election_tokens_decrypt uuid_s in
        redir_preapply election_home (uuid, ()) ()
      ) else forbidden ()
    )

let () =
  Any.register ~service:election_tally_release
    handle_election_tally_release

let content_type_of_file = function
  | ESRaw -> "application/json; charset=utf-8"
  | ESTParams | ESETally | ESResult -> "application/json"
  | ESKeys | ESBallots -> "text/plain" (* should be "application/json-seq", but we don't use RS *)
  | ESCreds | ESRecords | ESVoters -> "text/plain"

let handle_pseudo_file uuid f site_user =
  let confidential =
    match f with
    | ESRaw | ESKeys | ESTParams | ESBallots | ESETally | ESResult | ESCreds -> false
    | ESRecords | ESVoters -> true
  in
  let%lwt () =
    if confidential then (
      let%lwt metadata = Web_persist.get_election_metadata uuid in
      match site_user with
      | Some u when metadata.e_owner = Some u -> return ()
      | _ -> forbidden ()
    ) else return ()
  in
  let content_type = content_type_of_file f in
  File.send ~content_type (!spool_dir / raw_string_of_uuid uuid / string_of_election_file f)

let () =
  Any.register ~service:election_dir
    (fun (uuid, f) () ->
     let%lwt site_user = Web_state.get_site_user () in
     handle_pseudo_file uuid f site_user)

let () =
  Any.register ~service:election_compute_encrypted_tally
    (fun (uuid, ()) () ->
      with_site_user (fun u ->
          let%lwt election = find_election uuid in
          let%lwt metadata = Web_persist.get_election_metadata uuid in
          let module W = (val Election.get_group election) in
          let module E = Election.Make (W) (LwtRandom) in
          let module B = Web_election.Make (E) in
          if metadata.e_owner = Some u then (
            let%lwt () =
              match%lwt Web_persist.get_election_state uuid with
              | `Closed -> return ()
              | _ -> forbidden ()
            in
            let%lwt nb, hash, tally = B.compute_encrypted_tally () in
            let%lwt npks =
              match%lwt Web_persist.get_threshold uuid with
              | Some tp ->
                 let tp = threshold_parameters_of_string W.G.read tp in
                 return (Array.length tp.t_verification_keys)
              | None ->
                 match%lwt Web_persist.get_public_keys uuid with
                 | Some pks -> return (List.length pks)
                 | None -> failwith "missing public keys and threshold parameters"
            in
            Web_persist.set_election_state uuid (`EncryptedTally (npks, nb, hash)) >>
              let tally = encrypted_tally_of_string W.G.read tally in
              let%lwt sk = Web_persist.get_private_key uuid in
              match metadata.e_trustees with
              | None ->
                 (* no trustees: compute decryption and release tally *)
                 let sk = match sk with
                   | Some x -> x
                   | None -> failwith "missing private key"
                 in
                 let%lwt pd = E.compute_factor tally sk in
                 let pd = string_of_partial_decryption W.G.write pd in
                 Web_persist.set_partial_decryptions uuid [1, pd]
                 >> handle_election_tally_release (uuid, ()) ()
              | Some ts ->
                 Lwt_list.iteri_s (fun i t ->
                     if t = "server" then (
                       match%lwt Web_persist.get_private_key uuid with
                       | Some k ->
                          let%lwt pd = E.compute_factor tally k in
                          let pd = string_of_partial_decryption W.G.write pd in
                          Web_persist.set_partial_decryptions uuid [i+1, pd]
                       | None -> return_unit (* dead end *)
                     ) else return_unit
                   ) ts
                 >> redir_preapply election_admin (uuid, ()) ()
          ) else forbidden ()
        )
    )

let () =
  Any.register ~service:set_language
    (fun lang () ->
      Eliom_reference.set Web_state.language lang >>
      let%lwt cont = Web_state.cont_pop () in
      match cont with
      | Some f -> f ()
      | None -> Redirection.send home)

let () =
  Any.register ~service:election_setup_threshold_set
    (fun uuid threshold ->
      with_setup_election uuid (fun se ->
          match se.se_threshold_trustees with
          | None ->
             let msg = "Please add some trustees first!" in
             let service = preapply election_setup_threshold_trustees uuid in
             T.generic_page ~title:"Error" ~service msg () >>= Html5.send
          | Some xs ->
             let maybe_threshold, step =
               if threshold = 0 then None, None
               else Some threshold, Some 1
             in
             if threshold >= 0 && threshold < List.length xs then (
               List.iter (fun x -> x.stt_step <- step) xs;
               se.se_threshold <- maybe_threshold;
               redir_preapply election_setup_threshold_trustees uuid ()
             ) else (
               let msg = "The threshold must be positive and lesser than the number of trustees!" in
               let service = preapply election_setup_threshold_trustees uuid in
               T.generic_page ~title:"Error" ~service msg () >>= Html5.send
             )
        )
    )

let () =
  Any.register ~service:election_setup_threshold_trustee_add
    (fun uuid stt_id ->
      with_setup_election uuid (fun se ->
          if is_email stt_id then (
            let%lwt stt_token = generate_token () in
            let trustee = {
                stt_id; stt_token; stt_step = None;
                stt_cert = None; stt_polynomial = None;
                stt_vinput = None; stt_voutput = None;
              } in
            let trustees =
              match se.se_threshold_trustees with
              | None -> Some [trustee]
              | Some t -> Some (t @ [trustee])
            in
            se.se_threshold_trustees <- trustees;
            let%lwt () = Ocsipersist.add election_tpktokens stt_token (raw_string_of_uuid uuid) in
            redir_preapply election_setup_threshold_trustees uuid ()
          ) else (
            let msg = stt_id ^ " is not a valid e-mail address!" in
            let service = preapply election_setup_threshold_trustees uuid in
            T.generic_page ~title:"Error" ~service msg () >>= Html5.send
          )
        )
    )

let () =
  Any.register ~service:election_setup_threshold_trustee_del
    (fun uuid index ->
      with_setup_election uuid (fun se ->
          let trustees, old =
            let trustees =
              match se.se_threshold_trustees with
              | None -> []
              | Some x -> x
            in
            trustees |>
              List.mapi (fun i x -> i, x) |>
              List.partition (fun (i, _) -> i <> index) |>
              (fun (x, y) -> List.map snd x, List.map snd y)
          in
          let trustees = match trustees with [] -> None | x -> Some x in
          se.se_threshold_trustees <- trustees;
          let%lwt () =
            Lwt_list.iter_s (fun {stt_token; _} ->
                Ocsipersist.remove election_tpktokens stt_token
              ) old
          in
          redir_preapply election_setup_threshold_trustees uuid ()
        )
    )

let () =
  Html5.register ~service:election_setup_threshold_trustee
    (fun token () ->
      let%lwt uuid = Ocsipersist.find election_tpktokens token in
      let uuid = uuid_of_raw_string uuid in
      let%lwt se = get_setup_election uuid in
      T.election_setup_threshold_trustee token uuid se ()
    )

let () =
  Any.register ~service:election_setup_threshold_trustee_post
    (fun token data ->
      wrap_handler
        (fun () ->
          let%lwt uuid = Ocsipersist.find election_tpktokens token in
          let uuid = uuid_of_raw_string uuid in
          Lwt_mutex.with_lock election_setup_mutex
            (fun () ->
              let%lwt se = get_setup_election uuid in
              let ts =
                match se.se_threshold_trustees with
                | None -> failwith "No threshold trustees"
                | Some xs -> Array.of_list xs
              in
              let i, t =
                match Array.findi (fun i x ->
                          if token = x.stt_token then Some (i, x) else None
                        ) ts with
                | Some (i, t) -> i, t
                | None -> failwith "Trustee not found"
              in
              let get_certs () =
                let certs = Array.map (fun x ->
                                match x.stt_cert with
                                | None -> failwith "Missing certificate"
                                | Some y -> y
                              ) ts in
                {certs}
              in
              let get_polynomials () =
                Array.map (fun x ->
                    match x.stt_polynomial with
                    | None -> failwith "Missing polynomial"
                    | Some y -> y
                  ) ts
              in
              let module G = (val Group.of_string se.se_group : GROUP) in
              let module P = Trustees.MakePKI (G) (LwtRandom) in
              let module C = Trustees.MakeChannels (G) (LwtRandom) (P) in
              let module K = Trustees.MakePedersen (G) (LwtRandom) (P) (C) in
              (match t.stt_step with
               | Some 1 ->
                  let cert = cert_of_string data in
                  if K.step1_check cert then (
                    t.stt_cert <- Some cert;
                    t.stt_step <- Some 2;
                    return_unit
                  ) else (
                    failwith "Invalid certificate"
                  )
               | Some 3 ->
                  let certs = get_certs () in
                  let polynomial = polynomial_of_string data in
                  if K.step3_check certs i polynomial then (
                    t.stt_polynomial <- Some polynomial;
                    t.stt_step <- Some 4;
                    return_unit
                  ) else (
                    failwith "Invalid polynomial"
                  )
               | Some 5 ->
                  let certs = get_certs () in
                  let polynomials = get_polynomials () in
                  let voutput = voutput_of_string G.read data in
                  if K.step5_check certs i polynomials voutput then (
                    t.stt_voutput <- Some data;
                    t.stt_step <- Some 6;
                    return_unit
                  ) else (
                    failwith "Invalid voutput"
                  )
               | _ -> failwith "Unknown step"
              ) >> (
                if Array.forall (fun x -> x.stt_step = Some 2) ts then (
                  (try
                     K.step2 (get_certs ());
                     Array.iter (fun x -> x.stt_step <- Some 3) ts;
                   with e ->
                     se.se_threshold_error <- Some (Printexc.to_string e)
                  ); return_unit
                ) else return_unit
              ) >> (
                if Array.forall (fun x -> x.stt_step = Some 4) ts then (
                  (try
                     let certs = get_certs () in
                     let polynomials = get_polynomials () in
                     let vinputs = K.step4 certs polynomials in
                     for j = 0 to Array.length ts - 1 do
                       ts.(j).stt_vinput <- Some vinputs.(j)
                     done;
                     Array.iter (fun x -> x.stt_step <- Some 5) ts
                   with e ->
                     se.se_threshold_error <- Some (Printexc.to_string e)
                  ); return_unit
                ) else return_unit
              ) >> (
                if Array.forall (fun x -> x.stt_step = Some 6) ts then (
                  (try
                     let certs = get_certs () in
                     let polynomials = get_polynomials () in
                     let voutputs = Array.map (fun x ->
                                        match x.stt_voutput with
                                        | None -> failwith "Missing voutput"
                                        | Some y -> voutput_of_string G.read y
                                      ) ts in
                     let p = K.step6 certs polynomials voutputs in
                     se.se_threshold_parameters <- Some (string_of_threshold_parameters G.write p);
                     Array.iter (fun x -> x.stt_step <- Some 7) ts
                   with e ->
                     se.se_threshold_error <- Some (Printexc.to_string e)
                  ); return_unit
                ) else return_unit
              ) >> set_setup_election uuid se
            ) >>
            redir_preapply election_setup_threshold_trustee token ()
        )
    )
