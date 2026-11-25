------------------------------- MODULE Trace -------------------------------
(* Log, with the constants a trace needs, for trust/log's
   TestTheCodeFollowsTheModelsTraces to replay against the code: what each
   validator should see after each step is Log's res. *)
EXTENDS Log

VARIABLE setup

TraceInit ==
  /\ Init
  /\ setup = [keys |-> Keys, nodes |-> Nodes, validators |-> Validators,
              admins |-> GenesisAdmins, quorum |-> GenesisQuorum, members |-> GenesisNodes,
              paired |-> PairedKeys, pairNeeded |-> PairNeeded]

TraceSpec == TraceInit /\ [][Next /\ UNCHANGED setup]_<<vars, setup>>

=============================================================================
