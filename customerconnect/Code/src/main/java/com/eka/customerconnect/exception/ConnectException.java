
package com.eka.customerconnect.exception;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.eka.customerconnect.error.ConnectError;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ConnectException extends RuntimeException {
	/**
	 *         Base class for exception occurred while saving/storing file
	 */
private static final long serialVersionUID = -6580084539119446608L;

	
	private List<ConnectError> errors;
	private String errCodeMessage;
	private String errorCode;

	public String getErrorCode() {
		return errorCode;
	}
	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}
	public String getErrCodeMessage() {
		return errCodeMessage;
	}
	public void setErrCodeMessage(String errCodeMessage) {
		this.errCodeMessage = errCodeMessage;
	}
	public ConnectException() {
		super();
	}
	public ConnectException(List<ConnectError> errorResponce,String errorLocalizedMessage) {
		super(errorLocalizedMessage);
		this.setErrors(errorResponce);
	}
	public ConnectException(String message, Throwable cause) {
		super(message, cause);
	}

	public ConnectException(String message) {
		super(message);
	}

	public ConnectException(Throwable cause) {
		super(cause);
	}
	public ConnectException(String message, Throwable cause,String errCodeMessage) {
		super(message, cause);
		setErrCodeMessage(errCodeMessage);
	}
	public ConnectException(String message, Throwable cause,String errCodeMessage,String errorCode) {
		super(message, cause);
		setErrCodeMessage(errCodeMessage);
		setErrorCode(errorCode);
	}
	

	public ConnectException(List<ConnectError> errors2) {
		// TODO Auto-generated constructor stub
		this.setErrors(errors2);
	}

	public List<ConnectError> getErrors() {
		return errors;
	}

	public void setErrors(List<ConnectError> errors) {
		this.errors = errors;
	}
}
