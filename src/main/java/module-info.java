/**
 * JWhisper CLI client.
 */
module jwhisper.client.cli {
    requires static lombok;

    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires tools.jackson.core;
    requires tools.jackson.databind;
    requires org.slf4j;

    requires jwhisper.common;
}
