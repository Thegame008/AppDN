# AppDN 🔎

Analizador estático de tecnologías y protecciones presentes en aplicaciones Android e iOS. Examina nombres, rutas y contenido de APK e IPA, y muestra las evidencias que respaldan cada detección.

> El archivo se utiliza como `AppDN.py`. La versión actual conserva el nombre **MobScope 3.0.2** en la salida de consola.

## ¿Qué hace?

- Busca huellas de frameworks como Flutter, React Native, .NET MAUI, Xamarin, Capacitor, Cordova, Unity y Cocos.
- Identifica indicios de bibliotecas de seguridad, detección de root/jailbreak y componentes relacionados con SSL pinning.
- Reconoce componentes nativos ELF y Mach-O, además de huellas de lenguajes y runtimes.
- Lee metadatos de la aplicación cuando están disponibles y calcula el SHA-256 de las entradas.
- Analiza archivos internos con multihilos y permite exportar un informe JSON.

No ejecuta la aplicación ni necesita conectarse a Internet para analizarla. Una detección indica presencia de huellas; no demuestra que una protección esté activa ni que exista una vulnerabilidad.

## Requisitos

- Python **3.9 o superior**.
- Solo utiliza la biblioteca estándar: no requiere `pip install` ni herramientas adicionales.
- Un archivo o carpeta local para analizar.

## Inicio rápido en Windows

Descarga `AppDN.py`. Abre PowerShell en la carpeta donde lo guardaste y comprueba Python:

```powershell
python --version
python .\AppDN.py --help
```

Si tu instalación responde a `py` en lugar de `python`, sustituye `python` por `py` en los ejemplos. En Linux puedes utilizar `python3`.

Analiza tu primer APK:

```powershell
python .\AppDN.py "C:\Auditoria\aplicacion.apk"
```

## Ejemplos

### 1. Analizar un APK con selección automática de hilos

```powershell
python .\AppDN.py "C:\Auditoria\aplicacion.apk"
```

Utiliza hasta 4 hilos, según las CPU detectadas.

### 2. Analizar una IPA con 4 hilos

```powershell
python .\AppDN.py "C:\Auditoria\aplicacion.ipa" --threads 4
```

### 3. Mostrar más evidencias y guardar el informe

```powershell
python .\AppDN.py "C:\Auditoria\aplicacion.apk" --threads 4 --verbose --evidence 5 --json "C:\Auditoria\resultado.json"
```

`--verbose` muestra las muestras conservadas con sus rutas completas. `--evidence` controla cuántas huellas se presentan por tecnología en la vista resumida; no amplía las búsquedas ni elimina el máximo de tres muestras por regla y archivo. La carpeta de destino del JSON debe existir. Un JSON existente en esa ruta se sobrescribe.

### 4. Analizar los splits de una misma aplicación

```powershell
python .\AppDN.py "C:\Auditoria\base.apk" "C:\Auditoria\split_config.arm64_v8a.apk" --threads 4
```

También puedes indicar una carpeta; se recorren sus subcarpetas en busca de archivos compatibles:

```powershell
python .\AppDN.py "C:\Auditoria\splits" --threads 4
```

Las entradas se agregan en un mismo informe. Usa esta modalidad con componentes de la misma app; para aplicaciones distintas, realiza ejecuciones separadas.

### 5. Ejecutar en modo secuencial

```powershell
python .\AppDN.py "C:\Auditoria\aplicacion.apk" --threads 1
```

### 6. Aumentar los límites de lectura

```powershell
python .\AppDN.py "C:\Auditoria\aplicacion.apk" --threads 4 --max-file-mb 256 --max-total-mb 2048
```

Permite hasta 256 MiB por archivo interno y 2048 MiB de presupuesto acumulado. Puede aumentar el tiempo y el uso de recursos. El tamaño comprimido del APK/IPA no equivale al volumen que se leerá.

### 7. Consultar tecnologías o generar una salida sin animación

```powershell
python .\AppDN.py --list-technologies
python .\AppDN.py "C:\Auditoria\aplicacion.ipa" --no-progress --no-color --json resultado.json
```

## Opciones

| Opción | Función | Valor inicial |
|---|---|---|
| `--threads N` | Número de hilos para archivos internos de los contenedores; `1` activa el modo secuencial. | Hasta 4, según CPU |
| `--json RUTA` | Guarda el informe JSON. | Sin exportación |
| `--verbose` | Muestra rutas completas y todas las muestras conservadas. | Desactivado |
| `--evidence N` | Huellas distintas por tecnología en el resumen; una corroboración conserva sus dos huellas. | `2` |
| `--list-technologies` | Lista tecnologías y tipos de firmas sin analizar entradas. | Desactivado |
| `--no-progress` | Desactiva la animación. | Desactivado |
| `--color auto/always/never` | Selecciona el comportamiento del color. | `auto` |
| `--no-color` | Desactiva colores; equivale a `--color never`. | Desactivado |
| `--max-file-mb N` | Límite por archivo, en MiB. | `128` |
| `--max-total-mb N` | Presupuesto acumulado de lectura, en MiB. | `1024` |
| `--max-entries N` | Máximo de entradas por contenedor ZIP. | `20000` |
| `--max-ratio N` | Relación máxima entre tamaño descomprimido y comprimido. | `300` |
| `--version` | Muestra la versión. | — |
| `-h`, `--help` | Muestra la ayuda. | — |

## Cómo interpretar los resultados

| Evaluación en JSON | Significado |
|---|---|
| `EVIDENCIA_ESPECIFICA` | Huella específica o combinación de huellas que respalda la presencia del componente. |
| `PROBABLE` | Coincidencia compatible que requiere corroboración. |
| `INDICIO_NO_CONFIRMADO` | Mención débil que no permite confirmar la integración. |

Si aparece **análisis parcial**, consulta las incidencias: puede haber límites alcanzados, entradas cifradas o errores de lectura.

## Alcance y límites

- Admite APK, IPA, APKS, XAPK, AAB, ZIP y AAR, además de archivos compatibles sueltos y carpetas.
- Los hilos reparten archivos internos, no fragmentos de un único archivo. Los paquetes de entrada se procesan uno tras otro. Más hilos no garantizan menos tiempo.
- Mantiene las reglas, filtros y límites del análisis secuencial. No analiza indiscriminadamente todas las extensiones.
- Conserva hasta tres muestras por regla y archivo. No encontrar coincidencias no descarta tecnologías ofuscadas o sin firmas reconocibles.
- Procesa contenedores con profundidad `0`, `1` y `2`; no abre otro contenedor anidado desde la profundidad `2`.
- No descifra IPA ni regiones Mach-O marcadas como cifradas. Estas regiones se excluyen y se notifican.
- Detectar Rust no implica que exista RASP. Detectar una biblioteca de pinning tampoco demuestra su activación.

## Códigos de salida

| Código | Significado |
|---|---|
| `0` | Finalizó sin incidencias registradas; no significa ausencia de vulnerabilidades. |
| `1` | Hay incidencias: el análisis se considera incompleto. |
| `2` | Error fatal, argumentos inválidos o fallo al guardar el JSON. |
| `130` | Interrupción con `Ctrl+C`. |
