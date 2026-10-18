# agent-custody: resumen en español

*Resumen informal del [README](../../README.md) y de [SPEC.md](../../SPEC.md). Si hay diferencias, manda la versión en
inglés.*

Una bitácora de lo que hizo un agente de IA y de qué clave aprobó cada acción. Si alguien la modifica después, un
tercero que no confía en usted puede detectarlo.

Su agente cambió una regla del firewall a las 3 de la mañana. ¿Qué clave autorizó el cambio y cómo muestra que nadie
editó el registro después?

agent-custody es un formato de bitácora y un verificador de un solo archivo para responder esa pregunta. La bitácora
registra las acciones que el agente pidió y ejecutó, las decisiones de política, las aprobaciones humanas y lo que dijo
un revisor de un segundo proveedor de IA. Usted firma puntos de control (*checkpoints*) de la bitácora con una clave
que debe guardarse fuera del equipo del agente. Con la clave pública correspondiente, cualquiera puede comprobar que
las entradas que cubre un checkpoint no cambiaron desde que se firmó. El verificador es un único archivo de Python,
sin dependencias.

Estado: v0.1, experimental. El formato puede cambiar antes de 1.0.

## Para quién es

- Equipos cuyos agentes tienen acceso a sistemas de producción, credenciales o datos de clientes.
- MSP y MSSP cuyos agentes trabajan en entornos de clientes y que necesitan entregarles un registro que el cliente
  pueda comprobar.
- Pruebas de penetración y ejercicios de red team autorizados, donde cada paso debe remitir a una aprobación firmada.
- Auditores y clientes que quieren hacer la comprobación por su cuenta.

## Prueba en tres comandos

Requiere Python 3.10 o posterior. Revise antes `python3 --version`: macOS todavía trae 3.9 de fábrica, y el
verificador termina con error en versiones anteriores a 3.10.

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

El primer comando verifica una bitácora sintética y termina con código 0. El segundo altera una copia. El tercero
termina con código 1 e indica qué capa falló (`entry_hashes`).

## Cómo funciona

Cada entrada incluye el hash de la anterior. Un checkpoint firmado fija la raíz de un árbol de Merkle (RFC 6962) sobre
las entradas. El verificador revisa la bitácora por capas, y cada capa devuelve `ok`, `fail`, `not_checked` (faltó lo
necesario para comprobarla) o `unavailable` (este verificador no puede hacer esa comprobación). Nunca imprime un
"VÁLIDO" a secas.

## Qué lo distingue

1. El verificador contrasta las aprobaciones con las acciones. Se registra un resumen criptográfico de lo que vio la
   persona (`presented_digest`), y la persona puede firmar la aprobación con su propia clave. La capa `approval_gate`
   falla si una acción que exigía aprobación se ejecutó cuando su aprobación más reciente faltaba, era un rechazo o
   había caducado, si reutilizó una aprobación ya consumida por un intento anterior, o si se ejecutó después de una
   decisión `deny` que ninguna aprobación humana posterior levantó. Un `allow` posterior no levanta el `deny`.
2. La revisión entre proveedores tiene su propio tipo de evento, con autor, revisores y veredictos. Los nombres de
   proveedor los declara quien escribe la bitácora; nada los autentica.
3. Se puede leer entero: unas 1200 líneas de Python con solo la biblioteca estándar. Lo acompañan 69 vectores de
   prueba, entre ellos bitácoras alteradas, reordenadas, truncadas, trasplantadas entre cadenas, checkpoints firmados
   con otra clave, aprobaciones reutilizadas y pruebas de inclusión manipuladas, que deben fallar.

## Límites

La lista completa está en [LIMITS.md](../../LIMITS.md), en inglés. En resumen:

- No prueba que los eventos registrados ocurrieran, ni que no ocurriera nada más.
- No prueba que el equipo que escribe la bitácora estuviera libre de compromiso. Quien lo controle antes del
  checkpoint puede escribir una bitácora falsa pero coherente.
- Sin un checkpoint firmado y guardado fuera del alcance de quien escribe la bitácora, no se detecta el truncamiento
  ni la reescritura completa.
- La hora de cada entrada (`ts`) es la del reloj del equipo que escribe. Un sello de tiempo externo sobre el
  checkpoint solo acota cuándo existía el checkpoint.
- Una firma de aprobador muestra que quien tenía esa clave firmó esa aprobación, con su caducidad y su método, pero no
  cuándo la firmó. Vincular la clave con una persona le corresponde a su organización. Cada aprobación autoriza un
  solo intento.
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
documentación la escribieron asistentes de IA de dos proveedores, que también hicieron las revisiones previas a la
publicación. No ha
habido una auditoría de seguridad humana independiente. El proyecto no está afiliado a ningún proveedor de IA ni
respaldado por ellos.

## Licencias

Código Apache-2.0; las partes derivadas de RFC 8032 también están bajo BSD-3-Clause (IETF Trust; ver `NOTICE`).
Especificación y documentación, CC-BY-4.0. Algunas partes generadas por IA podrían no ser protegibles por derecho de
autor en algunas jurisdicciones; las licencias aplican en la medida en que existan derechos.
