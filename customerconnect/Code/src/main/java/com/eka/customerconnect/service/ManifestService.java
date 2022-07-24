package com.eka.customerconnect.service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Service;

import com.eka.customerconnect.commons.CommonService;
import com.eka.customerconnect.exception.ConnectException;



/**
 * The Class ManifestService.
 */
@Service
public class ManifestService {

	/** The Constant logger. */
	final static  Logger logger = ESAPI.getLogger(ManifestService.class);

	@Autowired
	CommonService commonService;

	/**
	 * Gets the manifest attributes.
	 *
	 * @return the manifest attributes
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public Attributes getManifestAttributes(){
		 Manifest mf=null;
		 InputStream resourceAsStream=null;
		 Attributes atts=null;
	    try {
	    	 resourceAsStream = SpringBootApplication.class.getResourceAsStream("/META-INF/MANIFEST.MF");
	 	     mf = new Manifest();
			 mf.read(resourceAsStream);
			 atts = mf.getMainAttributes();
		}catch (FileNotFoundException fno){
			logger.error(Logger.EVENT_FAILURE, fno.getLocalizedMessage(), fno);
			throw new ConnectException(commonService.getErrorMessage("SC035", "Unable to locate manifest file", "customerconnect"), fno);
		} catch (IOException ioe) {
			logger.error(Logger.EVENT_FAILURE, ioe.getLocalizedMessage(), ioe);
			throw new ConnectException(commonService.getErrorMessage("SC036", "Unable to read Manifest file", "customerconnect"), ioe);
		}
	    return atts;	    		
	}


}