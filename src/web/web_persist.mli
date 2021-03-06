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

open Serializable_t
open Common
open Web_serializable_t

type election_state =
  [ `Open
  | `Closed
  | `EncryptedTally of int * int * string
  | `Tallied of plaintext
  | `Archived
  ]
val get_election_state : uuid -> election_state Lwt.t
val set_election_state : uuid -> election_state -> unit Lwt.t

val get_election_date : uuid -> datetime Lwt.t
val set_election_date : uuid -> datetime -> unit Lwt.t

val get_partial_decryptions : uuid -> (int * string) list Lwt.t
val set_partial_decryptions : uuid -> (int * string) list -> unit Lwt.t

val get_auth_config : uuid option -> (string * (string * string list)) list Lwt.t
val set_auth_config : uuid option -> (string * (string * string list)) list -> unit Lwt.t

val get_raw_election : uuid -> string option Lwt.t
val get_election_metadata : uuid -> metadata Lwt.t
val get_election_result : uuid -> Yojson.Safe.json result option Lwt.t

val get_elections_by_owner : user -> uuid list Lwt.t

val get_voters : uuid -> string list option Lwt.t
val get_passwords : uuid -> (string * string) SMap.t option Lwt.t
val get_public_keys : uuid -> string list option Lwt.t
val get_private_key : uuid -> number option Lwt.t
val get_private_keys : uuid -> string list option Lwt.t
val get_threshold : uuid -> string option Lwt.t

val get_ballot_hashes : uuid -> string list Lwt.t
val get_ballot_by_hash : uuid -> string -> string option Lwt.t
