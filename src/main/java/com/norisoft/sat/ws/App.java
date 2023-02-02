package com.norisoft.sat.ws;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;

import com.norisoft.sat.ws.WSDescargaCFDI.ResultadoVerificaSolicitud;

/**
 * Test run
 *
 */
public class App {
	public static void main(String[] args) throws ParseException, IOException {

		InputStream cer = new FileInputStream(new File("fiel.cer"));
		InputStream key = new FileInputStream(new File("fiel.key"));
		String clave = "";

		String rfc = "XAXX010101000 ";

		WSDescargaCFDI solicitud = new WSDescargaCFDI(rfc, cer, key, clave);
		solicitud.autenticacion();
		String idSolicitud = solicitud.solicitud("2018-01-01", "2018-01-01", null, rfc,
				WSDescargaCFDI.TIPO_SOLICITUD_CFDI);
		ResultadoVerificaSolicitud resultado = solicitud.verificacion(idSolicitud);
		ArrayList<String> idPaquetes = solicitud.obtiener_ids_paquetes(Paths.get(resultado.getXml_resultado()));

		for (String idPaquete : idPaquetes) {
			String xml = solicitud.descargaPaquete(idPaquete);
			String zip = solicitud.extraer_zip_de_xml(Paths.get(xml));
			System.out.println(zip);
		}

	}
}
