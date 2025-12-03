# **Parecidómetro** – Detección de similitud entre ficheros para combatir el cibercrimen

Parecidómetro es una herramienta diseñada para **analizar ficheros y detectar similitudes entre ellos** utilizando *similarity hashing*, una técnica ampliamente utilizada en análisis de malware, forense digital y respuesta ante incidentes.

A diferencia de los hashes tradicionales (como SHA-256 o MD5), que cambian por completo ante la mínima modificación, los *hashes de similitud permiten medir “cuán parecido es un fichero a otro”*, incluso aunque hayan sido recompilados, alterados o ligeramente modificados.

Esta herramienta proporciona un **servicio sencillo pero potente** para almacenar, analizar y comparar ficheros, facilitando la identificación de variantes maliciosas y patrones ocultos usados por actores de cibercrimen.

# **¿Para qué sirve esta herramienta?**

Parecidómetro permite:

- Calcular múltiples hashes de un fichero, tanto tradicionales (SHA256, MD5) como de similitud (TLSH, SSDEEP).
- Detectar si un fichero ya existe en la base de datos y actualizar su metainformación.
- Construir una base de datos local con información relevante de cada análisis.
- Generar un índice de similitud para identificar archivos similares en segundos.
- Facilitar el trabajo de analistas de malware, equipos DFIR, CERTs/CSIRTs y fuerzas de seguridad.

Es, en esencia, un **motor de correlación de ficheros**, que permite descubrir conexiones que los hashes normales no son capaces de detectar.

# **¿Qué aporta? ¿Por qué es útil?**

## **1. Detecta variantes de malware**

Los atacantes cambian pequeñas partes del código para evadir firmas tradicionales.
Con similarity hashing podemos detectar que un archivo *modificado* es en realidad una variante casi idéntica de uno ya conocido.

## **2. Ayuda a los equipos de respuesta a incidentes (DFIR)**

Un incidente suele generar múltiples artefactos: scripts, binarios, herramientas modificadas…
La herramienta ayuda a relacionarlos entre sí y a compararlos con muestras anteriores.

## **3. Apoyo a fuerzas de seguridad y laboratorios**

Permite enlazar casos aparentemente aislados:
diferentes campañas que, gracias a su similitud, podrían pertenecer al *mismo actor o grupo criminal*.

## **4. Útil para empresas con grandes repositorios**

Detecta reutilización de código no autorizada, modificaciones sospechosas o binarios alterados.

## **5. Facilita la investigación y clasificación**

Cualquier universidad, centro de investigación o analista puede usarlo para:

* Clasificar grandes colecciones de malware
* Analizar evolución temporal de amenazas
* Crear datasets reproducibles

# **¿Qué es un hash de similitud?**

Un hash de similitud es una técnica que permite comparar ficheros por su parecido, no por igualdad exacta.
A diferencia de SHA-256, que cambia completamente si alteramos un solo byte, algoritmos como SSDEEP o TLSH pueden detectar cuando dos archivos son esencialmente la misma cosa, aunque hayan sido modificados.
Esto es fundamental para detectar variantes de malware, analizar campañas, correlacionar artefactos forenses y comprender la evolución de amenazas en ciberseguridad.

<details>
  <summary>Más información acerca de hashes de similitud</summary>
  
Un **hash de similitud** (*similarity hash*) es una representación de un fichero diseñada para que **archivos parecidos generen hashes también parecidos**.

Esto contrasta con un hash criptográfico como SHA-256:

| Si modificas 1 byte… | Resultado                                   |
| -------------------- | ------------------------------------------- |
| SHA-256              | → cambia completamente                      |
| SSDEEP, TLSH         | → cambia ligeramente pero conserva relación |

### Ejemplo conceptual

* Tienes un malware *m1.exe*.
* El atacante recompila una versión *m1_modified.exe* cambiando un comentario o una cadena.

**SHA-256 dirá:** “Son completamente diferentes.”
**TLSH o SSDEEP dirán:** “Se parecen al 98%.”

Eso permite:

* detectar variantes,
* agrupar familias,
* correlacionar campañas,
* evitar evasiones sencillas.

Los algoritmos que usamos:

### **TLSH (Trend Micro Locality Sensitive Hash)**

Genera un hash robusto para identificar similitud entre binarios.
Muy usado en análisis de malware.

### **SSDEEP**

Divide el fichero en bloques y genera un hash sensible a cambios.
Excelente para documentos, scripts, PDF, y binarios medianos.
  
</details>


# **Cómo funciona** (PENDIENTE DE REESCRIBIR)

1. Ejecutas el script pasándole ficheros o directorios.
2. La herramienta:

   * Calcula sus hashes.
   * Genera su metainformación.
   * Comprueba si ya existe en la base de datos.
   * Si existe → solo actualiza el nombre y fecha.
   * Si no existe → añade una nueva entrada completa.
3. La base de datos se guarda en `file_db.json`.
4. Puedes generar un índice de similitud para búsquedas rápidas.

# **Estructura de la base de datos**

Cada entrada se organiza así:

```json
{
  "SHA256": {
    "name": ["file1", "file2"],
    "size": 12400,
    "file_type": "application/pdf",
    "first_upload_date": "",
    "last_upload_date": "",
    "desc": "",
    "hashes": {
      "sha256": "",
      "md5": "",
      "tlsh": "",
      "ssdeep": ""
    }
  }
}
```

# **Ejemplo de uso** (PENDENTIE DE REESCRIBIR)

```bash
python3 similarityscan.py samples/
```

Procesa todos los ficheros del directorio.

# **Por qué este proyecto importa**

En un ecosistema donde el cibercrimen evoluciona continuamente, no basta con verificar la integridad exacta de un archivo.
**Necesitamos herramientas que comprendan la similitud, no solo la igualdad.**

SimilarityScan ayuda a **reclasar, correlacionar y descubrir amenazas** que de otra forma pasarían desapercibidas.

Es simple, portable y poderosa: perfecta para equipos de seguridad, investigadores y analistas.

# Autores (orden alfabético)
- [Alain "Str1ien" Villagrasa](https://github.com/Str1ien)
- [Daniel "Kifixo" Huici](https://github.com/danielhuici)
- [Razvan "Razvi" Raducu](https://github.com/RazviOverflow)

Este proyecto se ha desarrollado durante el [Hackathon Cyber Arena](https://eupt.unizar.es/noticia/hackaton-de-incibe) organizado como parte del Proyecto Estratégico C077.23 de INCIBE, desarrollado junto a la Universidad de Zaragoza y financiado por los fondos Next Generation EU.