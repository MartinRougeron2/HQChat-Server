# The two facts that distinguish one host from another. Everything else in this
# directory is identical on prod and pre-prod — which is the property that was
# impossible to guarantee when each box was configured by hand.
{ lib, ... }:
{
  options.hqcat = {
    stack = lib.mkOption {
      type = lib.types.enum [
        "prod"
        "preprod"
      ];
      description = "Which stack this host runs. Selects the GHCR channel tag and the paths under /etc/hqcat.";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      example = "chat.example.com";
      description = "Public hostname this origin serves behind Cloudflare.";
    };

    imageRepo = lib.mkOption {
      type = lib.types.str;
      default = "ghcr.io/YOUR-GITHUB-ACCOUNT/dissqus-server";
      description = "GHCR repository the app agent follows.";
    };

    admin = {
      sshKeys = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "ssh-ed25519 AAAAC3Nz... martin@laptop" ];
        description = ''
          Public keys allowed to log in as root. This is the ONLY way into the
          machine: password authentication is off and there are no other users.

          Nothing automated uses SSH — releases are pulled — so this list should
          contain exactly the humans who administer the box, and normally that
          is one key on one laptop.
        '';
      };

      totp = lib.mkEnableOption ''
        a second factor (TOTP) on SSH, on top of the key.

        Left OFF by default because enabling it on a host where you have not yet
        run `google-authenticator` locks you out of SSH entirely — recoverable
        only through the DigitalOcean web console. Enrol first, prove it works in
        a second session, then turn this on. See docs/runbooks/from-scratch.md
      '';
    };

    cacheUrl = lib.mkOption {
      type = lib.types.str;
      default = "https://cache.example.com";
      description = ''
        Public base URL of the Nix binary cache (the R2 bucket, fronted by
        Cloudflare). Hosts substitute prebuilt closures from here instead of
        evaluating or building anything locally.
      '';
    };

    cachePublicKey = lib.mkOption {
      type = lib.types.str;
      # Generated once by the bootstrap (see infra/nixos/README.md). The PUBLIC
      # half is safe to commit; the private half lives only in GitHub secrets.
      default = "REPLACE_ME_WITH_CACHE_PUBLIC_KEY";
      example = "hqcat-cache-1:hqA1...=";
      description = ''
        Public half of the signing key CI uses. Nix refuses any store path that
        is not signed by a trusted key, so this is what makes pulling from a
        bucket safe: a writable cache cannot inject an unsigned closure.
      '';
    };
  };
}
