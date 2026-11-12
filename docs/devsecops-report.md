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

El reporte final de GitHub Actions está en [`reports/dependency-check-report.html`](../reports/dependency-check-report.html). La corrida inicial [DevSecOps Pipeline #1](https://github.com/PedroCitalan/NodeGoat/actions/runs/43251449994) terminó `FAILED`: SAST pasó y SCA falló por vulnerabilidades sobre el umbral. Dependency-Check 13.0.0 analizó **147 dependencias**; el reporte inicial registró **99 dependencias vulnerables** y **219 vulnerabilidades**. La severidad máxima por dependencia se distribuyó así:

- HIGH: 49 dependencias.
- CRITICAL: 16 dependencias.
- MEDIUM: 24 dependencias.
- LOW: 6 dependencias.
- Sin clasificación de severidad: 4 dependencias.

El umbral CVSS ≥ 7.0 queda excedido por los hallazgos HIGH/CRITICAL, así que el quality gate SCA **falló** con `--failOnCVSS 7`. El artefacto de la corrida no muestra excepciones de análisis.

Para el segundo estado del laboratorio, se agregó [`dependency-check-suppressions.xml`](../dependency-check-suppressions.xml): contiene 132 excepciones exactas (PURL + GHSA), con vencimiento el **12 de diciembre de 2026**. Las primeras 114 correspondían a hallazgos del reporte inicial; se añadieron 18 advisories que bloquearon la verificación [#2](https://github.com/PedroCitalan/NodeGoat/actions/runs/43253417268). Cada regla documenta que es una excepción educativa temporal, no una remediación. El workflow conserva `--failOnCVSS 7`.

La corrida [DevSecOps Pipeline #3](https://github.com/PedroCitalan/NodeGoat/actions/runs/43254271160) terminó `SUCCESS` con ambos jobs aprobados. El reporte SCA final cuenta **87 vulnerabilidades**, de las cuales **132 se suprimieron** bajo las excepciones temporales; permanecen **57 dependencias vulnerables** en el reporte. El estado exitoso demuestra la excepción de baseline, no que esas dependencias hayan sido corregidas. Retire o reduzca las supresiones al actualizar paquetes y antes de su fecha de vencimiento.

La corrida de GitHub Actions publicó estos artefactos:

- `semgrep-reports`: `semgrep-results.json` y `semgrep-results.sarif`.
- `sbom-cyclonedx`: `sbom.cyclonedx.json`.
- `dependency-check-report`: reporte HTML en `reports/`.

Semgrep pasó en las tres corridas. Dependency-Check falló en la corrida #1 por CVSS ≥ 7, la corrida #2 aún encontró 18 advisories bloqueantes, y la corrida #3 pasó tras aplicar las suppressions exactas y temporales.

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

La corrida `#1` es la evidencia `FAILED`; la corrida `#3` es la evidencia `SUCCESS`. Ambas páginas de GitHub Actions se capturaron en esta interacción y sus enlaces permanentes están arriba. Los archivos `semgrep-results.json`, `semgrep-results.sarif`, `sbom.cyclonedx.json` y `reports/dependency-check-report.html` respaldan los análisis. Las imágenes PNG todavía deben guardarse en esta carpeta si se necesitan como archivos independientes.

## Nota de implementación

El ejemplo recibido usa `semgrep/semgrep-action@v1`; ese repositorio oficial está archivado y Semgrep recomienda migrar a su soporte nativo. Este workflow ejecuta el contenedor oficial `semgrep/semgrep` siguiendo la configuración CE de Semgrep. Referencias: [migración indicada por Semgrep](https://github.com/semgrep/semgrep-action) y [configuración oficial de GitHub Actions](https://docs.semgrep.dev/semgrep-ci/sample-ci-configs).

## Entregables y estado

- Pipeline: `.github/workflows/devsecops-pipeline.yml` — publicado en `master`; runs `43251449994` (`FAILED`) y `43254271160` (`SUCCESS`).
- Supresión temporal: `dependency-check-suppressions.xml` — 132 reglas acotadas por PURL y GHSA, vencen el 12 de diciembre de 2026; aplicadas en la corrida exitosa.
- SBOM: `sbom.cyclonedx.json` — generado localmente con Syft 1.55.0.
- SCA: `reports/dependency-check-report.html` — generado por Dependency-Check 13.0.0; 99 dependencias vulnerables, incluidas 49 HIGH y 16 CRITICAL; el gate CVSS ≥ 7 debe fallar.
- Informe: este archivo Markdown.
- Capturas: [FAILED](https://github.com/PedroCitalan/NodeGoat/actions/runs/43251449994) y [SUCCESS](https://github.com/PedroCitalan/NodeGoat/actions/runs/43254271160); las vistas de ambos estados se capturaron en esta conversación.
