package io.standardcore.security;

public class PasswordHashException extends RuntimeException {
    public PasswordHashException(String message, Throwable innerException){
        super(message, innerException);
    }

    public PasswordHashException(String message){
        super(message);
    }

    public PasswordHashException(Throwable innerException){
        super(innerException);
    }
}
