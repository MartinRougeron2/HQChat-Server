# Pre-production: identical to prod by construction, differing only in the facts
# below. That equivalence is the point of moving host config here — it was
# impossible to assert when each box was configured by hand.
{
  hqcat.stack = "preprod";
  hqcat.domain = "preprod.chat.example.com";

  hqcat.net.publicV4 = "139.59.167.8/20";
  hqcat.net.gatewayV4 = "139.59.160.1";
  hqcat.net.anchorV4 = "10.16.0.7/16";
  hqcat.net.vpcV4 = "10.106.0.4/20";
}
