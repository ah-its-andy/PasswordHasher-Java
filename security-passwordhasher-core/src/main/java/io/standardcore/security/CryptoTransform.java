package io.standardcore.security;

public interface CryptoTransform {
    byte[] transformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
}
