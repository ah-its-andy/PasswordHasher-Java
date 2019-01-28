package io.standardcore.security;

public class BlockTransformException extends PasswordHashException {
    public BlockTransformException(String message, Throwable innerException) {
        super(message, innerException);
    }

    public BlockTransformException(String message) {
        super(message);
    }

    public BlockTransformException(Throwable innerException) {
        super(innerException);
    }
}
