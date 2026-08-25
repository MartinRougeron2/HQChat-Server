# Who can get into these machines. One file, applied to every host.
#
# Nothing automated uses SSH — the app and the OS are both pulled, so CI never
# connects to a server. That means this list has no service accounts in it and
# no break-glass key "for the pipeline": it is the humans who administer the
# boxes, and normally that is one key on one laptop.
{
  hqcat.admin = {
    sshKeys = [
      # Replace with your public key (cat ~/.ssh/id_ed25519.pub).
      # Evaluation fails while this list is empty — deliberately, because a host
      # with no key and no password has no way in at all.
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICDVXbtAt7thKmgjRO5gVDmiEDCOPCI9Z7ATziyA2H7V martinrougeron@Martins-MacBook-Pro.local"
    ];

    # Second factor on SSH. Turn on ONLY after running `google-authenticator`
    # as root on each host and confirming a fresh session works — enabling it
    # first locks you out, recoverable only via the DigitalOcean web console.
    #
    #   ssh root@<host> google-authenticator -t -d -f -r 3 -R 30 -w 8
    #   ssh root@<host> true      # in a NEW terminal: expect a code prompt
    #
    # Then flip this, merge, and wait for the host agent to pick it up.
    totp = false;
  };
}
