# norisis-sat-WSdescarga
Webservice de descarga masiva SAT
2020-08

Conexión al WS del SAT para descargar los XML 


- Paso 0: Llamado al login (Se requiere para el resto de las solicitudes)
- Paso 1: Solicitar una descarga. Recordar que se tienen limites de solicitud por parte del sat.
- Paso 2: Verifica el estado de la solicitud de la descarga usando el IdSolicitud generado.
- Paso 3: Descargar XML y extraer .ZIP#


```
String rfc = "XAXX010101000";
InputStream cer = new FileInputStream(new File("certificado_fiel.cer"));				
InputStream key = new FileInputStream(new File("llave_fiel.key"));
String clave = "12345678a";
WSDescargaCFDI solicitud = new WSDescargaCFDI(rfc,cer,key,clave);


// 0. Autentica
solicitud.autenticacion();

// 1. Solicita descarga
//El tipo de solicitud puede ser CFDI o Metadata
String IdSolicitud = solicitud.solicitud("2018-01-01","2018-01-01","AAA101010ABC",null,WSDescargaCFDI.TIPO_SOLICITUD_CFDI);


// 2. Obtiene Estado. 
ResultadoVerificaSolicitud resultado = solicitud.verificacion(idSolicitud);

// Si el EstadoSolicitud es 3 entonces podemos obtener los ids de paquete y procesarlos

// 3 Descargar XML y extraer zip

ArrayList<String> idPaquetes = solicitud.obtiener_ids_paquetes(Paths.get(resultado.getXml_resultado()));	
    
for (String idPaquete : idPaquetes) {
	String xml = solicitud.descargaPaquete(idPaquete);
   String zip = solicitud.extraer_zip_de_xml(Paths.get(xml));
   System.out.println(zip);
}

```
		
		
## Opciones

- solicitud.setEnviaSolicitud(false); // Genera solo el XML no lo envia
- solicitud.setGuardaSolicitud(true); // Guarda el XML de la solicitud  

## Requisitos
Se debe cargar la FIEL, no el certificado

## Todos:
- Completar flujo
- Parametrizar
- Validar que solo use la fiel
- Parametrizar tipo de solicitud (CFDI o metadata)
- Completar para solicitar los recibidos
- VValidar y probar solicitud de que las fecha de iniciio es anterior a la fecha de termino
- Validar RFCs  de solicitud y configuracion
- Prueba obtiener_ids_paquetes

## Referencias

+ <https://developers.sw.com.mx/knowledge-base/consumo-webservice-descarga-masiva-sat/>
+ <https://github.com/lunasoft/sw-descargamasiva-php>
+ <https://www.sat.gob.mx/consultas/42968/consulta-y-recuperacion-de-comprobantes-(nuevo)>

## Códigos

Tipos de respuestas a las solicitudes

*EstadoSolicitud*
- Aceptada=1
- EnProceso=2
- **Terminada=3**
- Error=4
- Rechazada=5
- Vencida=6

* En relación a la solicitud vía Web Services*

Código	Mensaje  

**5000	Solicitud recibida con éxito**  
5002	Se agotó las solicitudes de por vida  
5004	No se encontró la información  
5005	Solicitud duplicada

5007	No existe el paquete solicitado
5008	Máximo de descargas permitidas
  
404	Error no controlado  


*En cuando a la verificación vía Web Service.*  

Evento	Mensaje  
300	Usuario no válido  
301	XML mal formado  
302	Sello mal formado  
303	Sello no corresponde con RFC solicitante  
304	Certificado revocado o caduco  
305	Certificado inválido  
5000	Solicitud recibida con éxito  
5004	No se encontró la solicitud  

# Limites 

Con esta funcionalidad, podrás recuperar hasta 200 mil registros por petición y hasta un millón en metadata.    
No existe limitante en cuanto al número de solicitudes siempre que no se descargue en más de dos ocasiones un XML. 