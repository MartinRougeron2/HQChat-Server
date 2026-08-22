# Pre-production: identical to prod by construction, differing only in the two
# facts below. That equivalence is the point of moving host config here — it was
# impossible to assert when each box was configured by hand.
{
  hqcat.stack = "preprod";
  hqcat.domain = "preprod.chat.example.com";
}
