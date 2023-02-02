package com.norisoft.sat.ws;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.UUID;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.apache.commons.ssl.PKCS8Key;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class WSDescargaCFDI {

	private static final Logger logger = LogManager.getLogger(WSDescargaCFDI.class);

	private static final String URL_TIME_SERVER = "1.mx.pool.ntp.org";
	private static final String FORMATO_TIMESTAMP = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
	private static final String FORMATO_TIMESTAMP_CORTO = "yyyy-MM-dd'T'00:00:00";
	private static final String FORMATO_TIMESTAMP_CORTO_T = "yyyy-MM-dd'T'23:59:59";

	private static final String WS_URL_AUTENTICACION = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc";
	private static final String WS_URL_SOLICITUD = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
	private static final String WS_URL_VERIFICACION = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc";
	private static final String WS_URL_DESCARGA = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc";

	private static final String WS_SOAP_ACTION_AUTENTICACION = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica";
	private static final String WS_SOAP_ACTION_SOLICITUD = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga";
	private static final String WS_SOAP_ACTION_VERIFICACION = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga";
	private static final String WS_SOAP_ACTION_DESCARGA = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar";

	private static String DIR_SALIDA = "/output/dir";
	private String RFC_SOLICITANTE = "XAXX010101000 ";

	public static final MediaType MT_JSON = MediaType.get("text/xml; charset=utf-8");
	public static final String TIPO_SOLICITUD_CFDI = "CFDI";
	public static final String TIPO_SOLICITUD_METADATOS = "METADATA";

	private String AutenticaResult = null;
	private String IdSolicitud = null;
	private String idPaquete = null;
	private String solicitud_mensaje = null;
	private String solicitud_codigo = null;

	public String getSolicitud_codigo() {
		return solicitud_codigo;
	}

	private boolean ENVIA_SOLICITUD = true;
	private boolean GUARDA_SOLICITUD = false;
	HashMap<String, String> resultado = null;

	public String getSolicitud_mensaje() {
		return solicitud_mensaje;
	}

	public String getAutenticaResult() {
		return AutenticaResult;
	}

	public String getIdSolicitud() {
		return IdSolicitud;
	}

	public String getIdPaquete() {
		return idPaquete;
	}

	public void setAutenticaResult(String autenticaResult) {
		AutenticaResult = autenticaResult;
	}

	public void setEnviaSolicitud(boolean b) {
		ENVIA_SOLICITUD = b;
	}

	public void setGuardaSolicitud(boolean b) {
		GUARDA_SOLICITUD = b;
	}

	private X509Certificate certificado;
	private PrivateKey private_key;

	/**
	 * Obtiene la fecha hora de servidor de tiempo para evitar problemas con reloj
	 * desincronziado local
	 * 
	 * @return FechaHora de servidor de tiempo
	 */
	private static Date obtenerFechaGMT() {
		try {
			TimeInfo timeInfo = new NTPUDPClient().getTime(InetAddress.getByName(URL_TIME_SERVER));
			long returnTime = timeInfo.getMessage().getTransmitTimeStamp().getTime();
			return new Date(returnTime);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	}

	static PrivateKey loadPKCS8PrivateKey(InputStream in, String passwd) throws Exception {
		byte[] decrypted = new PKCS8Key(in, passwd.toCharArray()).getDecryptedBytes();
		PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec(decrypted);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(keysp);
	}

	public void autenticacion() {

		if (private_key == null)
			return;

		logger.info("Generando xml autenticación");

		this.AutenticaResult = null;
		this.resultado = null;

		try {

			DateFormat gmtFormat = new SimpleDateFormat(FORMATO_TIMESTAMP);
			gmtFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

			Date fecha_ntp = obtenerFechaGMT();

			Calendar cal = Calendar.getInstance();
			cal.setTime(fecha_ntp);
			cal.add(Calendar.MINUTE, 5);

			String fecha_i = gmtFormat.format(fecha_ntp);
			String fecha_t = gmtFormat.format(cal.getTime());

			String uuid = "uuid-" + UUID.randomUUID().toString().toLowerCase() + "-1";
			String cert = Base64.getEncoder().encodeToString(this.certificado.getEncoded());

			String digest_message = "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\"><u:Created>"
					+ fecha_i + "</u:Created><u:Expires>" + fecha_t + "</u:Expires></u:Timestamp>";

			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.reset();
			digest.update(digest_message.getBytes("utf8"));

			String digest_value = Base64.getEncoder().encodeToString(digest.digest());

			String signature_value_xml = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">"
					+ "</CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"#_0\">"
					+ "<Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms>"
					+ "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>"
					+ "<DigestValue>" + digest_value + "</DigestValue></Reference></SignedInfo>";

			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(private_key);
			sig.update(signature_value_xml.getBytes());

			String signature_value = Base64.getEncoder().encodeToString(sig.sign());
			StringWriter sw = new StringWriter();

			HashMap<String, Object> scopes = new HashMap<String, Object>();

			scopes.put("FECHA_INICIAL", fecha_i);
			scopes.put("FECHA_TERMINO", fecha_t);
			scopes.put("CERTIFICADO", cert);
			scopes.put("UUID", uuid);
			scopes.put("DIGEST_VALUE", digest_value);
			scopes.put("SIGNATURE_VALUE", signature_value);

			MustacheFactory mf = new DefaultMustacheFactory();
			Mustache mustache = mf.compile("descarga_login.mustache");
			mustache.execute(sw, scopes).flush();

			String xml_enviar = sw.toString().replace("\n", "").replace("\r", "").replace("\t", "");

			if (ENVIA_SOLICITUD) {
				HashMap<String, String> resultado = envia_solicitud(WS_URL_AUTENTICACION, WS_SOAP_ACTION_AUTENTICACION,
						xml_enviar);
				if (resultado != null && resultado.get("procesado").equals("true")) {

					InputSource inputSource = new InputSource(new StringReader(resultado.get("resultado")));
					XPath xpath = XPathFactory.newInstance().newXPath();
					this.AutenticaResult = xpath.evaluate("//*[local-name()='AutenticaResult']/text()", inputSource);
					logger.debug("AutenticaResult: {}", AutenticaResult);
				}
			} else {
				this.AutenticaResult = "0123456789";
			}

		} catch (CertificateEncodingException e) {
			logger.error(e, e);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e, e);
		} catch (UnsupportedEncodingException e) {
			logger.error(e, e);
		} catch (InvalidKeyException e) {
			logger.error(e, e);
		} catch (SignatureException e) {
			logger.error(e, e);
		} catch (IOException e) {
			logger.error(e, e);
		} catch (XPathExpressionException e) {
			logger.error(e, e);
		}

	}

	public String solicitud(String d_inicio, String d_termino, String rfc_emisor, String rfc_receptor,
			String tipo_solicitud) {

		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");

		try {
			return this.solicitud(format.parse(d_inicio), format.parse(d_termino), rfc_emisor, rfc_receptor,
					tipo_solicitud);
		} catch (ParseException e) {
			logger.error(e, e);
			return null;
		}

	}

	public String solicitud(Date d_inicio, Date d_termino, String rfc_emisor, String rfc_receptor,
			String tipo_solicitud) {

		try {
			SimpleDateFormat formato_corto = new SimpleDateFormat(FORMATO_TIMESTAMP_CORTO);
			SimpleDateFormat formato_corto_t = new SimpleDateFormat(FORMATO_TIMESTAMP_CORTO_T);
			String fecha_inicio = formato_corto.format(d_inicio);
			String fecha_termino = formato_corto_t.format(d_termino);

			logger.info("Solicitud {}:{} {}:{} ", fecha_inicio.substring(0, 10), fecha_termino.substring(0, 10),
					rfc_emisor, rfc_receptor);

			this.IdSolicitud = null;

			String certificado = Base64.getEncoder().encodeToString(this.certificado.getEncoded());
			String certificado_datosString = this.certificado.getIssuerX500Principal().toString();
			String certificado_serial_number = this.certificado.getSerialNumber().toString();

			String digest_message = "<des:SolicitaDescarga xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\">"
					+ "<des:solicitud ";
			if (rfc_emisor != null)
				digest_message += "RfcEmisor=\"" + rfc_emisor + "\" ";
			if (rfc_receptor != null)
				digest_message += "RfcReceptor=\"" + rfc_receptor + "\" ";
			digest_message += "RfcSolicitante=\"" + RFC_SOLICITANTE + "\"" + " FechaInicial=\"" + fecha_inicio
					+ "\" FechaFinal=\"" + fecha_termino + "\"" + " TipoSolicitud=\"" + tipo_solicitud
					+ "\"></des:solicitud></des:SolicitaDescarga>";

			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.reset();
			digest.update(digest_message.getBytes("utf8"));

			String digest_value = Base64.getEncoder().encodeToString(digest.digest());

			String signature_value_xml = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
					+ "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>"
					+ "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"\">"
					+ "<Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform></Transforms>"
					+ "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>"
					+ "<DigestValue>" + digest_value + "</DigestValue></Reference></SignedInfo>";

			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(private_key);
			sig.update(signature_value_xml.getBytes());
			String signature_value = Base64.getEncoder().encodeToString(sig.sign());

			HashMap<String, Object> scopes = new HashMap<String, Object>();

			scopes.put("FECHA_INICIAL", fecha_inicio);
			scopes.put("FECHA_TERMINO", fecha_termino);

			scopes.put("RFC_EMISOR", rfc_emisor);
			scopes.put("RFC_RECEPTOR", rfc_receptor);
			scopes.put("RFC_SOLICITANTE", RFC_SOLICITANTE);

			scopes.put("CERTIFICADO", certificado);

			scopes.put("TIPO_SOLICITUD", tipo_solicitud);

			scopes.put("DIGEST_VALUE", digest_value);
			scopes.put("SIGNATURE_VALUE", signature_value);

			scopes.put("ISSUER_NAME", certificado_datosString);
			scopes.put("SERIAL_NUMBER", certificado_serial_number);

			StringWriter sw = new StringWriter();

			MustacheFactory mf = new DefaultMustacheFactory();
			Mustache mustache = mf.compile("descarga_solicitud.mustache");
			mustache.execute(sw, scopes).flush();

			if (GUARDA_SOLICITUD) {
				SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
				String file_name_salida = "solicitud-salida-" + format.format(new Date()) + ".xml";
				Path guarda_solicitud = Paths.get(DIR_SALIDA, file_name_salida);

				FileWriter fw = new FileWriter(guarda_solicitud.toFile());
				mustache.execute(fw, scopes).flush();
				logger.debug("Solicitud guardada {}", guarda_solicitud);
			}

			///

			String xml_enviar = sw.toString().replace("\n", "").replace("\r", "").replace("\t", "");

			if (ENVIA_SOLICITUD) {
				HashMap<String, String> resultado = envia_solicitud(WS_URL_SOLICITUD, WS_SOAP_ACTION_SOLICITUD,
						xml_enviar);
				if (resultado != null && resultado.get("procesado").equals("true")) {

					InputSource inputSource = new InputSource(new StringReader(resultado.get("resultado")));

					DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
					DocumentBuilder db = dbf.newDocumentBuilder();
					Document document = db.parse(inputSource);

					XPath xpath = XPathFactory.newInstance().newXPath();

					String code = (String) xpath.evaluate("//*[local-name()='SolicitaDescargaResult']/@CodEstatus",
							document, XPathConstants.STRING);
					String mensaje = (String) xpath.evaluate("//*[local-name()='SolicitaDescargaResult']/@Mensaje",
							document, XPathConstants.STRING);
					logger.debug("{} {}", code, mensaje);

					this.solicitud_mensaje = code + mensaje;
					this.solicitud_codigo = code;

					if (this.solicitud_codigo.equals("5000")) {
						this.IdSolicitud = (String) xpath.evaluate(
								"//*[local-name()='SolicitaDescargaResult']/@IdSolicitud", document,
								XPathConstants.STRING);
						logger.debug("IdSolicitud {}", IdSolicitud);
						return this.IdSolicitud;

					}
				}
			} else {
				this.IdSolicitud = "abc3456789";
				return this.IdSolicitud;
			}

		} catch (CertificateEncodingException e) {
			logger.error(e, e);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e, e);
		} catch (UnsupportedEncodingException e) {
			logger.error(e, e);
		} catch (InvalidKeyException e) {
			logger.error(e, e);
		} catch (SignatureException e) {
			logger.error(e, e);
		} catch (IOException e) {
			logger.error(e, e);
		} catch (XPathExpressionException e) {
			logger.error(e, e);
		} catch (ParserConfigurationException e) {
			logger.error(e, e);
		} catch (SAXException e) {
			logger.error(e, e);
		}
		return null;

	}

	public ResultadoVerificaSolicitud verificacion(String idSolicitud) {

		try {

			this.IdSolicitud = idSolicitud;

			logger.info("verificacion {}", this.IdSolicitud);

			String certificado = Base64.getEncoder().encodeToString(this.certificado.getEncoded());
			String certificado_datosString = this.certificado.getIssuerX500Principal().toString();
			String certificado_serial_number = this.certificado.getSerialNumber().toString();

			String digest_message = "<des:VerificaSolicitudDescarga xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\">"
					+ "<des:solicitud IdSolicitud=\"" + this.IdSolicitud + "\" RfcSolicitante=\"" + RFC_SOLICITANTE
					+ "\"></des:solicitud></des:VerificaSolicitudDescarga>";

			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.reset();
			digest.update(digest_message.getBytes("utf8"));

			String digest_value = Base64.getEncoder().encodeToString(digest.digest());

			String signature_value_xml = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
					+ "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>"
					+ "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"\">"
					+ "<Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform></Transforms>"
					+ "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>"
					+ "<DigestValue>" + digest_value + "</DigestValue></Reference></SignedInfo>";

			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(private_key);
			sig.update(signature_value_xml.getBytes());
			String signature_value = Base64.getEncoder().encodeToString(sig.sign());

			HashMap<String, Object> scopes = new HashMap<String, Object>();

			scopes.put("ID_SOLICITUD", this.IdSolicitud);
			scopes.put("RFC_SOLICITANTE", RFC_SOLICITANTE);

			scopes.put("CERTIFICADO", certificado);
			scopes.put("DIGEST_VALUE", digest_value);
			scopes.put("SIGNATURE_VALUE", signature_value);

			scopes.put("ISSUER_NAME", certificado_datosString);
			scopes.put("SERIAL_NUMBER", certificado_serial_number);

			StringWriter sw = new StringWriter();

			MustacheFactory mf = new DefaultMustacheFactory();
			Mustache mustache = mf.compile("descarga_verificacion.mustache");
			mustache.execute(sw, scopes).flush();

			String xml_enviar = sw.toString().replace("\n", "").replace("\r", "").replace("\t", "");

			if (ENVIA_SOLICITUD) {
				HashMap<String, String> resultado = envia_solicitud(WS_URL_VERIFICACION, WS_SOAP_ACTION_VERIFICACION,
						xml_enviar);
				if (resultado != null && resultado.get("procesado").equals("true")) {

					InputSource inputSource = new InputSource(new StringReader(resultado.get("resultado")));

					SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
					String validacion_file = "v_" + idSolicitud + "_" + format.format(new Date()) + ".xml";
					Path xml_salida = Paths.get(DIR_SALIDA, validacion_file);

					Files.write(xml_salida, resultado.get("resultado").getBytes());
					logger.debug("XML generado en {}", xml_salida.toUri());

					DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
					DocumentBuilder db = dbf.newDocumentBuilder();
					Document document = db.parse(inputSource);

					XPath xpath = XPathFactory.newInstance().newXPath();

					String code = (String) xpath.evaluate(
							"//*[local-name()='VerificaSolicitudDescargaResult']/@CodEstatus", document,
							XPathConstants.STRING);
					String mensaje = (String) xpath.evaluate(
							"//*[local-name()='VerificaSolicitudDescargaResult']/@Mensaje", document,
							XPathConstants.STRING);

					logger.debug("{} {}", code, mensaje);

					this.solicitud_mensaje = code + mensaje;
					this.solicitud_codigo = code;

					if (this.solicitud_codigo.equals("5000")) {

						String codigo_estado_solicitud = (String) xpath.evaluate(
								"//*[local-name()='VerificaSolicitudDescargaResult']/@CodigoEstadoSolicitud", document,
								XPathConstants.STRING);
						String estado_solicitud = (String) xpath.evaluate(
								"//*[local-name()='VerificaSolicitudDescargaResult']/@EstadoSolicitud", document,
								XPathConstants.STRING);
						String no_cfdis = (String) xpath.evaluate(
								"//*[local-name()='VerificaSolicitudDescargaResult']/@NumeroCFDIs", document,
								XPathConstants.STRING);

						ResultadoVerificaSolicitud resultadoVerificacion = new ResultadoVerificaSolicitud(
								codigo_estado_solicitud, estado_solicitud, no_cfdis, xml_salida.toFile().getName());

						logger.debug("CodigoEstadoSolicitud {} '{}' EstadoSolicitud {} '{}' no_cfdis {}",
								codigo_estado_solicitud, resultadoVerificacion.getCodigoEstadoSolicitudMensaje(),
								estado_solicitud, resultadoVerificacion.getEstadoSolicitudMensaje(), no_cfdis);

						return resultadoVerificacion;

					}

				}
			} else {
				this.IdSolicitud = "abc987654321";
				return new ResultadoVerificaSolicitud(null, null, null, null);
			}

		} catch (CertificateEncodingException e) {
			logger.error(e, e);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e, e);
		} catch (UnsupportedEncodingException e) {
			logger.error(e, e);
		} catch (InvalidKeyException e) {
			logger.error(e, e);
		} catch (SignatureException e) {
			logger.error(e, e);
		} catch (IOException e) {
			logger.error(e, e);
		} catch (ParserConfigurationException e) {
			logger.error(e, e);
		} catch (SAXException e) {
			logger.error(e, e);
		} catch (XPathExpressionException e) {
			logger.error(e, e);
		}
		return null;

	}

	public String descargaPaquete(String idPaquete) {

		try {

			this.idPaquete = idPaquete;

			logger.info("Descarga paqueta {}", this.idPaquete);

			String certificado = Base64.getEncoder().encodeToString(this.certificado.getEncoded());
			String certificado_datosString = this.certificado.getIssuerX500Principal().toString();
			String certificado_serial_number = this.certificado.getSerialNumber().toString();

			String digest_message = "<des:PeticionDescargaMasivaTercerosEntrada xmlns:des=\"http://DescargaMasivaTerceros.sat.gob.mx\">"
					+ "<des:peticionDescarga IdPaquete=\"" + idPaquete + "\" RfcSolicitante=\"" + RFC_SOLICITANTE
					+ "\">" + "</des:peticionDescarga></des:PeticionDescargaMasivaTercerosEntrada>";

			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.reset();
			digest.update(digest_message.getBytes("utf8"));

			String digest_value = Base64.getEncoder().encodeToString(digest.digest());

			String signature_value_xml = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
					+ "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod>"
					+ "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"\">"
					+ "<Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms>"
					+ "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>"
					+ "<DigestValue>" + digest_value + "</DigestValue></Reference></SignedInfo>";

			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(private_key);
			sig.update(signature_value_xml.getBytes());
			String signature_value = Base64.getEncoder().encodeToString(sig.sign());

			HashMap<String, Object> scopes = new HashMap<String, Object>();

			scopes.put("ID_PAQUETE", this.idPaquete);
			scopes.put("RFC_SOLICITANTE", RFC_SOLICITANTE);

			scopes.put("CERTIFICADO", certificado);
			scopes.put("DIGEST_VALUE", digest_value);
			scopes.put("SIGNATURE_VALUE", signature_value);

			scopes.put("ISSUER_NAME", certificado_datosString);
			scopes.put("SERIAL_NUMBER", certificado_serial_number);

			StringWriter sw = new StringWriter();

			MustacheFactory mf = new DefaultMustacheFactory();
			Mustache mustache = mf.compile("descarga_descarga.mustache");
			mustache.execute(sw, scopes).flush();

			if (GUARDA_SOLICITUD) {
				SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
				String file_name_salida = "solicitud-descarga-" + format.format(new Date()) + ".xml";
				Path guarda_solicitud = Paths.get(DIR_SALIDA, file_name_salida);

				FileWriter fw = new FileWriter(guarda_solicitud.toFile());
				mustache.execute(fw, scopes).flush();
				logger.debug("Solicitud guardada {}", guarda_solicitud);
			}

			String xml_enviar = sw.toString().replace("\n", "").replace("\r", "").replace("\t", "");

			if (ENVIA_SOLICITUD) {
				HashMap<String, String> resultado = envia_solicitud(WS_URL_DESCARGA, WS_SOAP_ACTION_DESCARGA,
						xml_enviar);
				if (resultado != null && resultado.get("procesado").equals("true")) {

					InputSource inputSource = new InputSource(new StringReader(resultado.get("resultado")));

					DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
					DocumentBuilder db = dbf.newDocumentBuilder();
					Document document = db.parse(inputSource);

					XPath xpath = XPathFactory.newInstance().newXPath();

					String code = (String) xpath.evaluate("//*[local-name()='respuesta']/@CodEstatus", document,
							XPathConstants.STRING);
					String mensaje = (String) xpath.evaluate("//*[local-name()='respuesta']/@Mensaje", document,
							XPathConstants.STRING);

					logger.debug("Codigo {} Mensaje {}", code, mensaje);

					this.solicitud_mensaje = code + mensaje;
					this.solicitud_codigo = code;

					if (code.equals("5000")) {
						SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
						String validacion_file = "p_" + idPaquete + "_" + format.format(new Date()) + ".xml";
						Path xml_salida = Paths.get(DIR_SALIDA, validacion_file);

						Files.write(xml_salida, resultado.get("resultado").getBytes());
						logger.debug("XML generado en {}", xml_salida.toUri());
						return xml_salida.toFile().getName();
					} else {
						return null;
					}

				}
			} else {
				this.idPaquete = "abc98765456789";
				return null;
			}

		} catch (CertificateEncodingException e) {
			logger.error(e, e);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e, e);
		} catch (UnsupportedEncodingException e) {
			logger.error(e, e);
		} catch (InvalidKeyException e) {
			logger.error(e, e);
		} catch (SignatureException e) {
			logger.error(e, e);
		} catch (IOException e) {
			logger.error(e, e);
		} catch (ParserConfigurationException e) {
			logger.error(e, e);
		} catch (SAXException e) {
			logger.error(e, e);
		} catch (XPathExpressionException e) {
			logger.error(e, e);
		}
		return null;

	}

	public WSDescargaCFDI() {

	}

	public static Date obtenerFechaCaducidadCertificado(InputStream certificado_stream) {

		try {
			CertificateFactory factory2 = CertificateFactory.getInstance("X.509");
			X509Certificate certificado = (X509Certificate) factory2.generateCertificate(certificado_stream);
			return certificado.getNotAfter();
		} catch (CertificateException e) {
			logger.error(e, e);
			return null;
		}

	}

	public WSDescargaCFDI(String rfc, InputStream certificado, InputStream private_key_file, String password) {

		if (rfc == null)
			throw new IllegalArgumentException("Cetificado no especificado");
		if (certificado == null)
			throw new IllegalArgumentException("Cetificado no especificado");
		if (private_key_file == null)
			throw new IllegalArgumentException("Private key no especificada");

		try {

			this.RFC_SOLICITANTE = rfc;

			CertificateFactory factory2 = CertificateFactory.getInstance("X.509");
			this.certificado = (X509Certificate) factory2.generateCertificate(certificado);
			this.certificado.checkValidity();

			private_key = WSDescargaCFDI.loadPKCS8PrivateKey(private_key_file, password);

		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			this.private_key = null;
			this.certificado = null;

		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			this.private_key = null;
			this.certificado = null;

		} catch (CertificateException e) {
			e.printStackTrace();
			this.private_key = null;
			this.certificado = null;

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			this.private_key = null;
			this.certificado = null;

		} catch (Exception e) {
			logger.error(e, e);
		}

	}

	private HashMap<String, String> envia_solicitud(String url, String soap_action, String xml) {
		logger.info("Enviando solicitud {} : {} ", url, soap_action);

		SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
		String action = soap_action.substring(soap_action.lastIndexOf('/') + 1).trim();
		String file_name_salida = action + "-" + format.format(new Date()) + ".xml";

		try {

			Path xml_salida = Paths.get(DIR_SALIDA, file_name_salida);

			if (!Paths.get(DIR_SALIDA).toFile().canWrite()) {
				logger.error("No fue posible generar archivo xml de salida {}", DIR_SALIDA);
				return null;
			}

			String auth_token = "";
			if (this.AutenticaResult != null) {
				auth_token = "WRAP access_token=\"" + AutenticaResult + "\"";
				logger.debug("Authorization {}", auth_token);
			}

			this.resultado = new HashMap<String, String>();

			OkHttpClient client = new OkHttpClient().newBuilder().build();
			RequestBody body = RequestBody.create(xml, MT_JSON);

			Request request = new Request.Builder().url(url).method("POST", body).addHeader("SOAPAction", soap_action)
					.addHeader("Authorization", auth_token).build();

			Response response = client.newCall(request).execute();

			if (response.isSuccessful())
				resultado.put("procesado", "true");
			else
				resultado.put("procesado", "false");

			logger.debug("Solicitud procesada {}-{} ", response.code(), response.message());

			resultado.put("status_code", response.code() + "");
			resultado.put("resultado", response.body().string());
			resultado.put("status", response.message());

			if (!soap_action.equals(WS_SOAP_ACTION_AUTENTICACION) && !soap_action.equals(WS_SOAP_ACTION_VERIFICACION)
					&& !soap_action.equals(WS_SOAP_ACTION_DESCARGA)) {
				Files.write(xml_salida, resultado.get("resultado").getBytes());
				logger.debug("XML generado en {}", xml_salida.toUri());
			}

			return resultado;

		} catch (IOException e) {
			logger.error(e, e);
			return null;
		}
	}

	public ArrayList<String> obtiener_ids_paquetes(Path xml_verificacion) {

		try {

			ArrayList<String> paquetes = new ArrayList<String>();
			InputStream is = new FileInputStream(xml_verificacion.toFile());

			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(is);

			XPath xpath = XPathFactory.newInstance().newXPath();

			String codigo_estado_solicitud = (String) xpath.evaluate(
					"//*[local-name()='VerificaSolicitudDescargaResult']/@CodigoEstadoSolicitud", document,
					XPathConstants.STRING);
			String estado_solicitud = (String) xpath.evaluate(
					"//*[local-name()='VerificaSolicitudDescargaResult']/@EstadoSolicitud", document,
					XPathConstants.STRING);

			if (codigo_estado_solicitud.equals("5000") && estado_solicitud.equals("3")) {

				NodeList result = (NodeList) xpath.evaluate("//*[local-name()='IdsPaquetes']", document,
						XPathConstants.NODESET);

				for (int i = 0; i < result.getLength(); i++) {
					Node n = result.item(i);
					paquetes.add(n.getTextContent());
				}

				return paquetes;
			}

		} catch (FileNotFoundException e) {
			logger.error(e, e);
		} catch (ParserConfigurationException e) {
			logger.error(e, e);
		} catch (SAXException e) {
			logger.error(e, e);
		} catch (IOException e) {
			logger.error(e, e);
		} catch (XPathExpressionException e) {
			logger.error(e, e);
		}

		return null;

	}

	public String extraer_zip_de_xml(Path xml_verificacion) {

		try {

			InputStream is = new FileInputStream(xml_verificacion.toFile());

			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(is);

			XPath xpath = XPathFactory.newInstance().newXPath();

			String codigo_estado_solicitud = (String) xpath.evaluate("//*[local-name()='respuesta']/@CodEstatus",
					document, XPathConstants.STRING);

			if (codigo_estado_solicitud.equals("5000")) {

				String data = (String) xpath.evaluate("//*[local-name()='Paquete']", document, XPathConstants.STRING);

				byte[] data_file = Base64.getDecoder().decode(data);
				String zip_file = xml_verificacion.toString();
				zip_file = zip_file.substring(0, zip_file.lastIndexOf(".xml")) + ".zip";

				Files.write(Paths.get(zip_file), data_file);
				return zip_file.toString();
			}

		} catch (FileNotFoundException e) {
			logger.error(e, e);
		} catch (ParserConfigurationException e) {
			logger.error(e, e);
		} catch (SAXException e) {
			logger.error(e, e);
		} catch (IOException e) {
			logger.error(e, e);
		} catch (XPathExpressionException e) {
			logger.error(e, e);
		}

		return null;

	}

	public class ResultadoVerificaSolicitud {

		private String CodigoEstadoSolicitud;
		private String EstadoSolicitud;
		private String no_cfdis;
		private String xml_resultado;

		ResultadoVerificaSolicitud(String CodigoEstadoSolicitud, String EstadoSolicitud, String no_cfdis, String xml) {

			this.CodigoEstadoSolicitud = CodigoEstadoSolicitud;
			this.EstadoSolicitud = EstadoSolicitud;
			this.no_cfdis = no_cfdis;
			this.xml_resultado = xml;

		}

		public String getCodigoEstadoSolicitud() {
			return CodigoEstadoSolicitud;
		}

		public String getEstadoSolicitud() {
			return EstadoSolicitud;
		}

		public String getNo_cfdis() {
			return no_cfdis;
		}

		public String getXml_resultado() {
			return xml_resultado;
		}

		public String getCodigoEstadoSolicitudMensaje() {
			switch (CodigoEstadoSolicitud) {
			case "5000":
				return "Solicitud recibida con éxito ";
			case "5002":
				return "Se agotó las solicitudes de por vida ";
			case "5003":
				return "Tope máximo ";
			case "5004":
				return "No se encontró la información";
			case "5005":
				return "Solicitud duplicada";
			default:
				return CodigoEstadoSolicitud;
			}
		}

		public String getEstadoSolicitudMensaje() {
			switch (EstadoSolicitud) {
			case "1":
				return "Aceptada";
			case "2":
				return "EnProceso";
			case "3":
				return "Terminada";
			case "4":
				return "Error";
			case "5":
				return "Rechazada";
			case "6":
				return "Vencida";
			default:
				return EstadoSolicitud;
			}
		}

	}

}
