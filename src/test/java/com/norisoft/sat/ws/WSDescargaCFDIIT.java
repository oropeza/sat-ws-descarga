package com.norisoft.sat.ws;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.xml.sax.InputSource;

import com.norisoft.sat.ws.WSDescargaCFDI.ResultadoVerificaSolicitud;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Paths;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

class WSDescargaCFDIIT {

	@Test
	@DisplayName("Solicitud de autenticación")
	@Disabled
	void solicitud_de_login() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.autenticacion();
		assertNotNull(solicitud.getAutenticaResult());

	}

	@Test
	@DisplayName("Autenticación XML")
	void autenticacion_xmll() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.setEnviaSolicitud(false);
		solicitud.autenticacion();

		assertEquals("0123456789", solicitud.getAutenticaResult());

	}

	@Test
	@DisplayName("Solicitud sin procesar")
	void solicitud_xml() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.setEnviaSolicitud(false);
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		try {
			solicitud.solicitud(format.parse("2018-10-10"), format.parse("2018-10-20"), "AUAC4601138F9",
					"AUAC4601138F9", "CFDI");
		} catch (ParseException e) {
			e.printStackTrace();
		}

		assertEquals("abc3456789", solicitud.getIdSolicitud());

	}

	@Test
	@DisplayName("Solicitud  300 token invalido")
	void solicitud_sin_token() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		try {
			String token = solicitud.solicitud(format.parse("2018-10-10"), format.parse("2018-10-20"), "AUAC4601138F9",
					"AUAC4601138F9", "CFDI");
			assertNull(token);
			assertEquals("300", solicitud.getSolicitud_codigo()); // 300 Token invalido.
		} catch (ParseException e) {
			e.printStackTrace();
		}

	}

	@Test
	@DisplayName("Solicitud 305 certificado invalido")
	void solicitud_certificado_novalido() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.autenticacion();
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		try {
			String token = solicitud.solicitud(format.parse("2018-10-10"), format.parse("2018-10-20"), "AUAC4601138F9",
					"AUAC4601138F9", "CFDI");
			assertNull(token);
			assertEquals("305", solicitud.getSolicitud_codigo()); // 305 Certificado Inválido
		} catch (ParseException e) {
			e.printStackTrace();
		}

	}

	@Test
	@DisplayName("Verificacion sin procesar")
	void verificacion_xml() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.setEnviaSolicitud(false);
		solicitud.verificacion("de7f98b6-d20f-44de-ab19-b312b489eec2");
		assertEquals("abc987654321", solicitud.getIdSolicitud());

	}

	@Test
	@DisplayName("Verificacion  300 token invalido")
	void verificacion_sin_token() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		ResultadoVerificaSolicitud resultado = solicitud.verificacion("1d68b4da-0929-4da1-978a-adbfbb3720ac");
		assertNull(resultado);
		assertEquals("300", solicitud.getSolicitud_codigo()); // 300 Token invalido.

	}

	@Test
	@DisplayName("Verificacion 305 certificado invalido")
	void verificacion_certificado_novalido() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.autenticacion();
		ResultadoVerificaSolicitud resultado = solicitud.verificacion("1d68b4da-0929-4da1-978a-adbfbb3720ac");
		assertNull(resultado);
		assertEquals("305", solicitud.getSolicitud_codigo()); // 305 Certificado Inválido

	}

	@Test
	@DisplayName("Verificacion 301 XML MAL FORMADO")
	void verificacion_certificado_xml_mal_formado() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.autenticacion();
		ResultadoVerificaSolicitud resultado = solicitud.verificacion("XXXX");
		assertNull(resultado);
		assertEquals("301", solicitud.getSolicitud_codigo()); // xml mal formado

	}

	@Test
	@DisplayName("Lectura XML de verificacion")
	void lectura_xml_verificacion() {

		WSDescargaCFDI solicitud = new WSDescargaCFDI();
		ArrayList<String> resultados = solicitud.obtiener_ids_paquetes(
				Paths.get("src/test/resources/v_47ac6c1b-66f3-46a0-93c8-053d695e819a_20200818194823.xml"));

		assertEquals("47AC6C1B-66F3-46A0-93C8-053D695E819A_01", resultados.get(0)); // xml mal formado
		assertEquals("47AC6C1B-66F3-46A0-93C8-053D695E819A_02", resultados.get(1)); // xml mal formado

	}

	@Test
	@DisplayName("Descarga sin procesar")
	void descarga_xml() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.setEnviaSolicitud(false);
		solicitud.descargaPaquete("47AC6C1B-66F3-46A0-93C8-053D695E819A_01");
		assertEquals("abc98765456789", solicitud.getIdPaquete());

	}

	@Test
	@DisplayName("Descarga  300 token invalido")
	void descarga_sin_token() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.descargaPaquete("47AC6C1B-66F3-46A0-93C8-053D695E819A_01");
		assertEquals("300", solicitud.getSolicitud_codigo()); // 300 Token invalido.

	}

	@Test
	@DisplayName("Descarga 305 certificado invalido")
	void descarga_certificado_novalido() {

		InputStream cer = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.cer");
		InputStream key = ClassLoader.class.getResourceAsStream("/FIEL_Pruebas_AUAC4601138F9.key");
		String clave = "12345678a";

		WSDescargaCFDI solicitud = new WSDescargaCFDI("AUAC4601138F9", cer, key, clave);
		solicitud.autenticacion();
		solicitud.descargaPaquete("47AC6C1B-66F3-46A0-93C8-053D695E819A_01");
		assertEquals("305", solicitud.getSolicitud_codigo()); // 305 Certificado Inválido

	}

}