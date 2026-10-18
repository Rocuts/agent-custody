# agent-custody: resumen en español

*Resumen informal del [README](../../README.md) y de [SPEC.md](../../SPEC.md). En caso de diferencia, manda la versión en inglés.*

**agent-custody** es un formato de bitácora y un verificador para registrar, de forma **evidente ante alteraciones**
(tamper-evident) y **verificable por un tercero**, lo que hace un agente de IA, qué decisiones de política se tomaron,
qué aprobó el titular de una clave de aprobador y qué dijo un segundo proveedor de IA al revisar el trabajo.

> Estado: **v0.1, experimental**. El formato puede cambiar antes de 1.0. Sin revisión de seguridad independiente.

## Qué problema resuelve

Cuando un agente cambia algo importante, "confíe en nuestros registros" es una respuesta débil. Aquí cada entrada se
encadena con la anterior mediante un hash; un punto de control (*checkpoint*) firmado fija la raíz de un árbol de
Merkle (RFC 6962); y un verificador de **un solo archivo de Python, solo biblioteca estándar**, comprueba capa por capa
si algo cambió desde el punto de control.

## Prueba en tres comandos

Requiere Python 3.10+ (el verificador se niega a correr en versiones anteriores).

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

El segundo comando altera una copia; el tercero termina con código 1 e indica qué capas fallaron.

## Qué lo distingue

1. **Aprobaciones humanas como evento de primera clase**: se registra qué vio la persona (`presented_digest`), puede
   firmarla con su propia clave, y la capa `approval_gate` falla si el registro muestra una acción que exigía
   aprobación ejecutada antes de ella, sin ella o después de un rechazo, o cualquier acción ejecutada después de una
   decisión `deny` que ninguna aprobación humana posterior levantó (un `allow` posterior no la levanta).
2. **Verificación cruzada entre proveedores** como tipo de evento (autor y revisores, con veredictos).
3. **Verificador honesto**: cada capa devuelve `ok`, `fail`, `not_checked` (no se aportó lo necesario) o `unavailable`
   (el verificador no puede hacer esa comprobación). Nunca imprime un "VÁLIDO" sin matices.
4. **Sin dependencias**; vectores de prueba que **deben fallar** (alterado, reordenado, truncado, trasplantado entre
   cadenas, checkpoint con firma ajena, aprobación reutilizada, prueba de inclusión manipulada).

## Qué NO prueba (resumen; ver [LIMITS.md](../../LIMITS.md), en inglés)

- No prueba que los eventos registrados ocurrieron realmente, ni que no ocurrió nada más.
- No prueba que el equipo que escribe el registro estuviera libre de compromiso: quien lo controle **antes** del
  checkpoint puede escribir un registro falso pero consistente.
- Sin un checkpoint firmado guardado fuera del alcance de quien escribe el registro, el truncamiento o la reescritura
  completa **no se detectan**.
- La hora de cada entrada (`ts`) es la del equipo que escribe. Solo un sello de tiempo externo sobre el checkpoint acota
  cuándo existía el checkpoint.
- Una firma de aprobador demuestra que quien tenía esa clave firmó esa aprobación (incluidos su caducidad y su método),
  no cuándo la firmó; asociar la clave a una persona es un paso organizativo. Cada aprobación autoriza un solo intento.
- **No es una firma electrónica con efectos jurídicos, no es un servicio de sellado de tiempo y no es una certificación
  de cumplimiento.** Que una evidencia sea aceptada depende de la ley local y de los contratos; consulte a un abogado
  de su jurisdicción.
- Con un único operador y sin testigos, este puede mostrar historias distintas a audiencias distintas.

## Contenido del repositorio

`SPEC.md` (formato y modelo de amenazas), `LIMITS.md` (límites), `verifier/` (verificador), `writer/` (escritor de
referencia, solo demostración), `vectors/` (vectores), `examples/` (tres ejemplos sintéticos), `skills/agent-custody/`
(skill para agentes), `tests/`.

## Cómo se construyó

Los mantenedores diseñaron y dirigieron el proyecto y responden por él. La mayor parte del código, las pruebas y la
documentación se redactó con asistentes de IA de dos proveedores distintos, y las revisiones previas a la publicación
(criptografía, seguridad, licencias, documentación) también se hicieron con ayuda de IA; sus hallazgos se corrigieron
con pruebas y vectores que forman parte de la suite. No ha habido una auditoría de seguridad humana independiente. El
proyecto no está afiliado a ningún proveedor de IA ni patrocinado por ellos. Algunas partes generadas por IA podrían no
ser protegibles por derecho de autor en algunas jurisdicciones; las licencias aplican en la medida en que existan
derechos.

Licencias: código Apache-2.0, con las partes derivadas de RFC 8032 también bajo BSD-3-Clause (IETF Trust; ver
`NOTICE`); especificación y documentación CC-BY-4.0.
