# Informe del laboratorio DevSecOps — NodeGoat

**Fecha de preparación:** 12 de noviembre de 2026  
**Alcance:** Fases 2–5: SAST, SCA, SBOM CycloneDX y quality gate.

## Resumen ejecutivo

Se configuró `.github/workflows/devsecops-pipeline.yml` para ejecutarse en `push` y `pull_request` hacia `main`/`master`, además de permitir una ejecución manual. El workflow contiene dos jobs independientes:

- **SAST:** Semgrep desde la imagen oficial `semgrep/semgrep`, usando `p/security-audit`; genera JSON y SARIF. El gate falla ante hallazgos con severidad `ERROR` o impacto `HIGH`/`CRITICAL`.
- **SCA y SBOM:** Syft mediante `anchore/sbom-action` genera `sbom.cyclonedx.json`; OWASP Dependency-Check produce un reporte HTML y falla con `--failOnCVSS 7`.

Los jobs son independientes para que un fallo de análisis no impida generar y publicar los artefactos del otro análisis.

## Resultados de análisis

### SAST — Semgrep

Semgrep escaneó 78 archivos rastreados por Git con `p/security-audit` (31 reglas aplicables). Encontró **1 hallazgo** en `app/views/profile.html:78`: posible XSS en una URL de plantilla (`generic.html-templates.security.var-in-href.var-in-href`), severidad `WARNING`, impacto `MEDIUM` y confianza `LOW`. El quality gate solicitado bloquea `ERROR` y `HIGH`/`CRITICAL`; este hallazgo no alcanza ese umbral, por lo que el gate SAST local **pasa**. Los reportes JSON y SARIF están disponibles en la raíz del repositorio.

Semgrep inicialmente falló dentro del sandbox al crear `socketpair` (`EACCES`). Ejecutado con permisos ampliados, el JSON se generó; para SARIF también fue necesario habilitar UTF-8 para evitar un error de codificación de Windows.

### SBOM — Syft

Syft 1.55.0 generó [`sbom.cyclonedx.json`](../sbom.cyclonedx.json), un documento CycloneDX 1.7 con **427 componentes** detectados. Se generó localmente; Syft informó que no pudo consultar su servidor de versiones por falta de DNS, pero la generación terminó con código 0.

### SCA — OWASP Dependency-Check

El reporte generado está en [`reports/dependency-check-report.html`](../reports/dependency-check-report.html). Dependency-Check 13.0.0 analizó **147 dependencias**; reportó **99 dependencias vulnerables** y **219 vulnerabilidades**. La severidad máxima por dependencia se distribuye así:

- HIGH: 49 dependencias.
- CRITICAL: 16 dependencias.
- MEDIUM: 25 dependencias.
- LOW: 6 dependencias.
- Sin clasificación de severidad: 3 dependencias.

El umbral CVSS ≥ 7.0 queda excedido por los hallazgos HIGH/CRITICAL, así que el quality gate SCA debe resultar **FAIL** con `--failOnCVSS 7`. El reporte también presenta dos excepciones `database has been closed` durante la actualización de datos KEV. Aunque el resumen y las vulnerabilidades se generaron, conviene repetir el análisis en una corrida limpia con la base NVD actualizada para confirmar que no haya resultados incompletos. No se registró aquí el código de salida de la corrida que generó el HTML; el resultado del gate se infiere de las severidades reportadas.

Al ejecutar el workflow en GitHub Actions, descargar estos artefactos desde la corrida:

- `semgrep-reports`: `semgrep-results.json` y `semgrep-results.sarif`.
- `sbom-cyclonedx`: `sbom.cyclonedx.json`.
- `dependency-check-report`: reporte HTML en `reports/`.

Semgrep pasa el umbral SAST local actual; Dependency-Check tiene resultados HIGH/CRITICAL que activan el gate configurado. Falta conservar la evidencia de estado de una corrida completa en GitHub Actions y una corrida posterior a la mitigación.

## Quality gate

| Análisis | Condición que falla el job |
| --- | --- |
| Semgrep | `extra.severity == ERROR` o `extra.metadata.impact` es `HIGH`/`CRITICAL` |
| Dependency-Check | CVSS ≥ 7.0 (`--failOnCVSS 7`) |

Para comprobar la transición a `SUCCESS`, corrija una dependencia/hallazgo y vuelva a ejecutar. Si se aplica una supresión, documente el identificador de regla/CVE, el motivo, el responsable y una fecha de revisión; la supresión no debe ocultar riesgos sin justificación.

## SBOM CycloneDX

El SBOM completo generado localmente está en [`sbom.cyclonedx.json`](../sbom.cyclonedx.json). A continuación se presentan sus primeras 30 líneas y un componente real detectado por Syft.

Primeras 30 líneas del SBOM:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:fa1d323c-f047-4d71-9d41-d6207f5b4522",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-12T09:02:24-06:00",
    "tools": {
      "components": [
        {
          "type": "application",
          "author": "anchore",
          "name": "syft",
          "version": "1.55.0"
        }
      ]
    },
    "component": {
      "bom-ref": "af63bd4c8601b7f1",
      "type": "file",
      "name": "."
    }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/abbrev@1.1.1?package-id=6802128969475f3d",
      "type": "library",
      "name": "abbrev",
      "version": "1.1.1"
```

Estructura del componente real `abbrev` (el SBOM completo incluye además licencia, CPE, `bom-ref` y propiedades de Syft):

```json
{
  "type": "library",
  "name": "abbrev",
  "version": "1.1.1",
  "purl": "pkg:npm/abbrev@1.1.1",
  "licenses": [{ "license": { "id": "ISC" } }]
}
```

Componente real: `abbrev` 1.1.1 (`pkg:npm/abbrev@1.1.1`), licencia ISC.

## Evidencias de GitHub Actions

La carpeta [`evidence/`](evidence/) está reservada para capturas reales de:

1. Una corrida `FAILED` con un hallazgo que active el gate.
2. Una corrida `SUCCESS` tras corregir o mitigar el hallazgo.
3. El resumen o artefactos de la corrida, si se requiere evidencia adicional.

No se generaron capturas porque GitHub Actions aún no se ha ejecutado para este cambio. Tras subir el workflow al repositorio y ejecutar ambas corridas, guardar las capturas en esa carpeta y sustituir esta nota por los nombres y una breve descripción de cada evidencia. Los archivos locales `semgrep-results.json`, `semgrep-results.sarif` y `sbom.cyclonedx.json` respaldan los análisis que sí se pudieron ejecutar.

## Nota de implementación

El ejemplo recibido usa `semgrep/semgrep-action@v1`; ese repositorio oficial está archivado y Semgrep recomienda migrar a su soporte nativo. Este workflow ejecuta el contenedor oficial `semgrep/semgrep` siguiendo la configuración CE de Semgrep. Referencias: [migración indicada por Semgrep](https://github.com/semgrep/semgrep-action) y [configuración oficial de GitHub Actions](https://docs.semgrep.dev/semgrep-ci/sample-ci-configs).

## Entregables y estado

- Pipeline: `.github/workflows/devsecops-pipeline.yml` — configurado; pendiente de corrida en GitHub Actions.
- SBOM: `sbom.cyclonedx.json` — generado localmente con Syft 1.55.0.
- SCA: `reports/dependency-check-report.html` — generado por Dependency-Check 13.0.0; 99 dependencias vulnerables, incluidas 49 HIGH y 16 CRITICAL; el gate CVSS ≥ 7 debe fallar.
- Informe: este archivo Markdown.
- Capturas: pendientes de las corridas reales en GitHub; directorio preparado en `docs/evidence/`.
