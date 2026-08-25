# Production. Facts only — everything else comes from ../modules.
{
  hqcat.stack = "prod";
  hqcat.domain = "chat.example.com";

  hqcat.net.publicV4 = "178.128.171.214/20";
  hqcat.net.gatewayV4 = "178.128.160.1";
  hqcat.net.anchorV4 = "10.16.0.6/16";
  hqcat.net.vpcV4 = "10.106.0.3/20";
}
