#!/bin/bash

set -e

BELENIOS=${BELENIOS:-$PWD}

alias belenios-tool=$BELENIOS/_build/belenios-tool

header () {
    echo
    echo "=-=-= $1 =-=-="
    echo
}

header "Setup election"

UUID=`uuidgen`
echo "UUID of the election is $UUID"

DIR=$BELENIOS/demo/data/$UUID
mkdir $DIR
cd $DIR

# Common options
uuid="--uuid $UUID"
group="--group $BELENIOS/demo/groups/default.json"
threshold="--trustees 3 --threshold 2"

# Generate credentials
belenios-tool credgen $uuid $group --count 3
mv *.pubcreds public_creds.txt
mv *.privcreds private_creds.txt

# Generate trustee keys
belenios-tool trustee-keygen $group $threshold --trustee-id 1
belenios-tool trustee-keygen $group $threshold --trustee-id 2
belenios-tool trustee-keygen $group $threshold --trustee-id 3

# Second step (check that nobody cheated)
belenios-tool trustee-keygen $group $threshold --trustee-id 1 --second-step
belenios-tool trustee-keygen $group $threshold --trustee-id 2 --second-step
belenios-tool trustee-keygen $group $threshold --trustee-id 3 --second-step

# Generate election parameters
belenios-tool mkelection $uuid $group --template $BELENIOS/demo/templates/election.json $threshold

header "Simulate votes"

cat private_creds.txt | while read cred; do
    belenios-tool election --privkey <(echo $cred) vote <(printf "[[0,0,0,0,0],[0,1,0,1,1,0],[0,0,1]]")
    echo >&2
done > ballots.tmp
mv ballots.tmp ballots.jsons

header "Perform decryption"

for u in `seq 1 3`; do
    belenios-tool election --privkey secret_share_$u.json decrypt --trustee-id $u
    echo >&2
done > partial_decryptions.tmp
mv partial_decryptions.tmp partial_decryptions.jsons

header "Finalize tally"

belenios-tool election finalize

echo
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo
echo "The simulated election was successful! Its result can be seen in"
echo "  $DIR/result.json"
echo
echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo
