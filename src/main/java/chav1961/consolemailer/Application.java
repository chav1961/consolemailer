package chav1961.consolemailer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Set;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.sun.mail.util.BASE64EncoderStream;

import chav1961.purelib.basic.ArgParser;
import chav1961.purelib.basic.URIUtils;
import chav1961.purelib.basic.Utils;
import chav1961.purelib.basic.exceptions.CommandLineParametersException;

public class Application {
	public static final String	CONFIG_FILE = ".consolemailer.props";
	public static final String	MODE_KEY = "mode";
	public static final String	URI_KEY = "uri";
	public static final String	KEYSTORE_KEY = "ks";
	public static final String	KEYSTORE_PASSWORD_KEY = "kspwd";
	public static final String	THEME_KEY = "theme";
	public static final String	SENDER_KEY = "sender";
	public static final String	RECEIVERS_KEY = "receivers";
	public static final String	CONF_KEY = "conf";

	private static final Set<String>	SCHEMES = new HashSet<>();
	// sendMail https://chav1961@smtp.mail.ru?pwd=*** -ks e:/chav1961/temp/ks.certs -kspwd sasa21 -receivers chav1961@mail.ru -theme "test message"
	// getCertificate https://smtp.mail.ru -ks e:/chav1961/temp/ks.certs -kspwd sasa21
	static {
		SCHEMES.add("http");
		SCHEMES.add("https");
	}
	
	public enum ApplicationMode {
		sendMail, getCertificate
	}
	
	
	public static void main(String[] args) {
		final ArgParser	parser = new ApplicationArgParser();
		
		try{final ArgParser	ap = parser.parse(args);
		
			switch (ap.getValue(MODE_KEY, ApplicationMode.class)) {
				case getCertificate	:
					getCertificates(ap);
					break;
				case sendMail		:
					sendMail(ap);
					break;
				default				:
					throw new UnsupportedOperationException("Application mode ["+ap.getValue(MODE_KEY, ApplicationMode.class)+"] is not supported yet");
			}
		} catch (CommandLineParametersException e) {
			System.err.println("Error parsing command line arguments: "+e.getLocalizedMessage());
			System.err.println(parser.getUsage("consolemailer"));
			System.exit(128);
		}
	}

	private static void getCertificates(final ArgParser parser) throws CommandLineParametersException {
		try{final URI				serverUri = parser.getValue(URI_KEY,URI.class);
			final String			host = serverUri.getHost();
			final int				port = serverUri.getPort();

	        if (!SCHEMES.contains(serverUri.getScheme())) {
	        	throw new IOException("Invalid URI ["+serverUri+"] to get certificates: must be absoulte and can use 'http' or 'https' schemes only");
	        }
			
	        final Hashtable<String, String[]> 	query = URIUtils.parseQuery(serverUri);	// zzz?type={SSL|TLSv1|...}
			final TrustManager[]	emptyTrustManagers = new TrustManager[]{
										       new X509TrustManager() {
										           public java.security.cert.X509Certificate[] getAcceptedIssuers() {
										              return null;
										            }
										            public void checkClientTrusted(X509Certificate[] certs, String authType) { }
										            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
										        }
										   };
			final SSLContext 		sslContext = SSLContext.getInstance(query.getOrDefault("type",new String[] {"TLSv1"})[0]);
			
			sslContext.init(null, emptyTrustManagers,  new java.security.SecureRandom());
			
			final SSLSocketFactory	sslsocketfactory = (SSLSocketFactory) sslContext.getSocketFactory();
			
			final KeyStore			ks = getKeyStore(parser);
			boolean					hasNewCert = false;
			
			try(final SSLSocket 	sock = (SSLSocket)sslsocketfactory.createSocket(host,port == -1 ? 465 : port);) {
				
				for (Certificate item : sock.getSession().getPeerCertificates()) {
					ks.setCertificateEntry(host+".cert",item);
					hasNewCert = true;
				}
			}
			if (hasNewCert) {
				 final File			storeFile = new File(parser.getValue(KEYSTORE_KEY, String.class));
				 final String		passwd = parser.getValue(KEYSTORE_PASSWORD_KEY, String.class);
					 
				 try(final OutputStream	is = new FileOutputStream(storeFile)) {
					 ks.store(is,passwd.toCharArray());
				}
			}
		} catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | KeyManagementException exc) {
			System.err.println("Error getting certificates: "+exc.getLocalizedMessage());
			System.exit(129);
		}
	}	
	
	private static void sendMail(final ArgParser parser) throws CommandLineParametersException {
		try{final URI			serverUri = parser.getValue(URI_KEY,URI.class);
			final String		authority = serverUri.getAuthority();
			final String		host = serverUri.getHost();		// smtp.mail.ru
			final int			port = serverUri.getPort();		// 465
	        final Properties	props = new Properties();

	        if (!SCHEMES.contains(serverUri.getScheme())) {
	        	throw new MessagingException("Invalid URI ["+serverUri+"] to send EMail: must be absoulte and can use 'http' or 'https' schemes only");
	        }
	        
			if (parser.isTyped(KEYSTORE_KEY)) {
				final File		f = new File(parser.getValue(KEYSTORE_KEY,String.class));
				
				if (f.exists() && f.isFile() && f.canRead()) {
			        System.setProperty("javax.net.ssl.keyStore", parser.getValue(KEYSTORE_KEY,String.class));
			        System.setProperty("javax.net.ssl.trustStore", parser.getValue(KEYSTORE_KEY,String.class));
				}
				else {
					throw new MessagingException("Ket store address ["+f.getAbsolutePath()+"] not exists, is not a file or is not accessible"); 
				}
			}
			if (parser.isTyped(KEYSTORE_PASSWORD_KEY)) {
		        System.setProperty("javax.net.ssl.keyStorePassword", parser.getValue(KEYSTORE_PASSWORD_KEY,String.class));
		        System.setProperty("javax.net.ssl.trustStorePassword", parser.getValue(KEYSTORE_PASSWORD_KEY,String.class));
			}
			
//			System.setProperty("javax.net.debug","all");
			
	        props.put("mail.smtp.host", host);
	        props.put("mail.smtp.ssl.enable", "true");
	        props.put("mail.smtp.port", port == -1 ? 465 : port);
	        props.put("mail.smtp.auth", "true");
	        props.put("mail.debug", System.getProperty("mail.debug","false"));
			
	        final Hashtable<String, String[]> 	query = URIUtils.parseQuery(serverUri);	// zzz?pwd=<mail_password>
	        final javax.mail.Authenticator 		auth = new javax.mail.Authenticator() {
										            protected PasswordAuthentication getPasswordAuthentication() {
										            	final String[]	userAndPassword = authority.split("\\@");
										
										            	return new PasswordAuthentication(userAndPassword[0],query.getOrDefault("pwd",new String[] {""})[0]);
										            }
										        }; 
	
	        final Session 			session = Session.getDefaultInstance(props,auth);
            final Message 			msg = new MimeMessage(session);
            final String[]			receivers = parser.getValue(RECEIVERS_KEY,String[].class);
            final InternetAddress[]	list = new InternetAddress[receivers.length]; 

            for (int index = 0; index < list.length; index++) {
            	list[index] = new InternetAddress(receivers[index]);
            }
            
            msg.setFrom(new InternetAddress(parser.getValue(SENDER_KEY,String.class)));
            msg.setRecipients(Message.RecipientType.TO, list);
            msg.setSubject(parser.getValue(THEME_KEY,String.class));
            msg.setSentDate(new Date());

            try(final Reader		rdr = new InputStreamReader(System.in);
            	final Writer		wr = new StringWriter()) {
            	
            	Utils.copyStream(rdr,wr);
                msg.setText(wr.toString());
            } catch (IOException e) {
                msg.setText("Error processing Mail body :"+e.getLocalizedMessage());
			}

            Transport.send(msg);
        }
        catch (MessagingException exc) {
			System.err.println("Error sending E-mail: "+exc.getLocalizedMessage());
			System.exit(129);
        }
	}

	private static KeyStore getKeyStore(final ArgParser parser) throws IOException, CommandLineParametersException {
		 try{final KeyStore 	keyStore = KeyStore.getInstance("PKCS12");
			 final File			storeFile = new File(parser.getValue(KEYSTORE_KEY, String.class));
			 
			 if (storeFile.exists() && storeFile.isFile() && storeFile.canRead()) {
				 final String		passwd = parser.getValue(KEYSTORE_PASSWORD_KEY, String.class);
				 
				 if (passwd != null) {
					 try(final InputStream	is = new FileInputStream(storeFile)) {
						 keyStore.load(is,passwd.toCharArray());
					 }
				 }
				 else {
					 throw new IOException("Mandatory key ["+KEYSTORE_PASSWORD_KEY+"] is missing in the command line string");
				 }
			 }
			 return keyStore;
		 } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException exc) {
			 throw new IOException("Keystore loading error: "+exc.getLocalizedMessage());
		 }
	}
	
	static class ApplicationArgParser extends ArgParser {
		public ApplicationArgParser() {
			super(new EnumArg<ApplicationMode>("mode",ApplicationMode.class,true,true,"Mode to start application. "+Arrays.toString(ApplicationMode.values())+" are available"),
				  new URIArg("uri",true,true,"Mail server URI in format 'smtp[s]:'<user>/<password>@<host>[:<port>]"),
			  	  new ConfigArg("conf",false,"config file with defaults ("+CONFIG_FILE+" if not typed)",CONFIG_FILE),
				  new URIArg("ks",false,"Key store file location","./keystore.certs"),
			  	  new StringArg("kspwd",false,false,"Key store password"),
			  	  new StringArg("theme",false,false,"mail theme as '<text>'"),
			  	  new StringArg("sender",false,"mail sender in <user>@<mailServer> format","chav1961@mail.ru"),
			  	  new StringListArg("receivers",false,false,"mail receivers in <user>@<mailServer> ... format"));
		}
	}
}
