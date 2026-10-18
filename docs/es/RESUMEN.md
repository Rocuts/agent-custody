# agent-custody: resumen en español

*Resumen informal del [README](../../README.md) y de [SPEC.md](../../SPEC.md). Si hay diferencias, manda la versión en
inglés.*

Bitácoras de lo que hizo un agente de IA y de qué clave lo aprobó, con alteraciones detectables por alguien que no
confía en usted.

Su agente cambió una regla del firewall a las 3 de la mañana. ¿Qué clave autorizó el cambio y cómo demuestra que nadie
editó el registro después?

agent-custody es un formato de bitácora y un verificador de un solo archivo para responder esa pregunta. La bitácora
registra lo que hizo el agente, las decisiones de política, qué aprobó el titular de una clave de aprobador y qué dijo
un segundo proveedor de IA al revisar el trabajo. Cualquiera que tenga la clave del punto de control (*checkpoint*)
puede comprobar que nada cambió desde que se firmó. El verificador es Python puro, sin dependencias.

Estado: v0.1, experimental. El formato puede cambiar antes de 1.0.

## Para quién es

- Equipos que operan agentes con acceso a producción: infraestructura, credenciales, datos de clientes.
- MSP y MSSP cuyos agentes actúan en entornos de clientes y necesitan entregarles un registro que puedan comprobar.
- Pruebas de penetración y red team autorizadas, donde cada paso debe remitir a una aprobación firmada.
- Auditores y clientes que quieren verificar el registro por su cuenta.

## Prueba en tres comandos

Requiere Python 3.10 o posterior; el verificador no corre en versiones anteriores. Algunos sistemas aún traen un
`python3` más viejo (macOS trae 3.9), así que revise `python3 --version` antes.

```sh
python3 verifier/agent_custody_verify.py examples/01-support-wifi-password/log.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)" \
  --approver-key "$(cat examples/01-support-wifi-password/approver-key.txt)"

sed 's/ap-guest-demo/ap-admin-demo/' examples/01-support-wifi-password/log.jsonl > /tmp/tampered.jsonl

python3 verifier/agent_custody_verify.py /tmp/tampered.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)"
```

El primero verifica una bitácora sintética y termina con código 0. El segundo altera una copia. El tercero termina con
código 1 e indica qué capa falló.

## Cómo funciona

Cada entrada se encadena con la anterior mediante un hash. Un punto de control firmado fija la raíz de un árbol de
Merkle (RFC 6962). El verificador comprueba, capa por capa, si algo cambió desde ese punto de control, y cada capa
devuelve `ok`, `fail`, `not_checked` (faltó lo necesario para comprobarla) o `unavailable` (el verificador no puede
hacer esa comprobación). Nunca imprime un "VÁLIDO" a secas.

## Qué lo distingue

1. Las aprobaciones se comprueban, no solo se guardan. Se registra un resumen de lo que vio la persona
   (`presented_digest`) y la aprobación puede firmarse con su propia clave. La capa `approval_gate` falla si el
   registro muestra una acción que exigía aprobación ejecutada antes de ella, sin ella o después de un rechazo, o
   cualquier acción ejecutada después de una decisión `deny` que ninguna aprobación humana posterior levantó (un
   `allow` posterior no la levanta).
2. La revisión entre proveedores es un tipo de evento, con autor, revisores y veredictos. Los nombres de proveedor los
   declara quien escribe la bitácora.
3. Es pequeño y se puede leer entero: un archivo de Python con solo la biblioteca estándar, más vectores de prueba que
   deben fallar (alterado, reordenado, truncado, trasplantado entre cadenas, checkpoint con firma ajena, aprobación
   reutilizada, prueba de inclusión manipulada).

## Límites

La lista completa está en [LIMITS.md](../../LIMITS.md), en inglés. En resumen:

- No prueba que los eventos registrados ocurrieran, ni que no ocurriera nada más.
- No prueba que el equipo que escribe la bitácora estuviera libre de compromiso. Quien lo controle antes del
  checkpoint puede escribir una bitácora falsa pero coherente.
- Sin un checkpoint firmado guardado fuera del alcance de quien escribe la bitácora, el truncamiento o la reescritura
  completa no se detectan.
- La hora de cada entrada (`ts`) es la del equipo que escribe. Solo un sello de tiempo externo sobre el checkpoint
  acota cuándo existía el checkpoint.
- Una firma de aprobador demuestra que quien tenía esa clave firmó esa aprobación, incluidos su caducidad y su método,
  pero no cuándo la firmó. Asociar la clave a una persona es un paso organizativo. Cada aprobación autoriza un solo
  intento.
- No es una firma electrónica con efectos jurídicos, ni un servicio de sellado de tiempo, ni una certificación de
  cumplimiento. Que una evidencia se acepte depende de la ley local y de los contratos; consulte a un abogado de su
  jurisdicción.
- Con un único operador y sin testigos, ese operador puede mostrar historias distintas a audiencias distintas.

## Contenido del repositorio

`SPEC.md` (formato y modelo de amenazas), `LIMITS.md` (límites), `verifier/` (verificador), `writer/` (escritor de
referencia, solo para demostración), `vectors/` (vectores), `examples/` (tres ejemplos sintéticos),
`skills/agent-custody/` (instrucciones para agentes), `tests/`.

## Cómo se construyó

Los mantenedores diseñaron y dirigieron el proyecto y responden por él. La mayor parte del código, las pruebas y la
documentación, y las revisiones previas a la publicación, se hicieron con asistentes de IA de dos proveedores. No ha
habido una auditoría de seguridad humana independiente, y el proyecto no está afiliado a ningún proveedor de IA ni
respaldado por ellos.

## Licencias

Código Apache-2.0; las partes derivadas de RFC 8032 también están bajo BSD-3-Clause (IETF Trust; ver `NOTICE`).
Especificación y documentación, CC-BY-4.0. Algunas partes generadas por IA podrían no ser protegibles por derecho de
autor en algunas jurisdicciones; las licencias aplican en la medida en que existan derechos.
