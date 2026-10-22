# Tarjeta de coordenadas

App para el móvil (PWA) que sustituye la tarjeta de coordenadas del banco. Pide un PIN de 6 dígitos al abrirla. Después escribes una coordenada (por ejemplo `C7`) y te devuelve su valor. Funciona sin conexión.

Los valores de la tarjeta **no están en ningún archivo**. Los introduces una vez dentro de la app, que los guarda cifrados con tu PIN solo en el almacenamiento de ese móvil. El repositorio de GitHub contiene solo el código, así que puede ser público sin problema.

## Archivos

```
index.html             pantallas de la app
styles.css             estilos (tema claro y oscuro automático)
app.js                 lógica y cifrado
sw.js                  service worker (funcionamiento sin conexión)
manifest.webmanifest   datos para instalarla como app
icons/                 iconos
```

## Publicarla en GitHub Pages

Se hace en unos 5 minutos desde el ordenador, con el navegador.

1. Entra en [github.com](https://github.com) con tu cuenta (o créala).
2. Arriba a la derecha pulsa **+** y luego **New repository**.
3. Ponle un nombre, por ejemplo `tarjeta`. Déjalo en **Public**. En el plan gratuito, GitHub Pages solo funciona con repositorios públicos, y aquí no hay ningún dato tuyo. Pulsa **Create repository**.
4. En la página del repositorio vacío, pulsa el enlace **uploading an existing file**.
5. Descomprime el zip y arrastra a la ventana **todo su contenido**: los cinco archivos y la carpeta `icons`. Comprueba que en la lista aparecen `icons/icon-192.png`, `icons/icon-512.png` e `icons/icon-maskable-512.png`. Si la carpeta no se sube, puedes crearla con **Add file → Upload files** y escribir `icons/` delante del nombre.
6. Abajo pulsa **Commit changes**.
7. Ve a **Settings** (pestaña del repositorio) → **Pages** (menú de la izquierda).
8. En **Build and deployment → Source** elige **Deploy from a branch**. En **Branch** elige `main` y `/ (root)`, y pulsa **Save**.
9. Espera uno o dos minutos y recarga esa página. Arriba aparecerá la dirección, del tipo:
   `https://TU-USUARIO.github.io/tarjeta/`

## Instalarla en el Android

1. Abre esa dirección en **Chrome** en el móvil.
2. Pulsa **Instalar en el móvil** en la app, o abre el menú **⋮** de Chrome y elige **Instalar aplicación** (o **Añadir a pantalla de inicio**).
3. Abre la app desde el icono nuevo y pulsa **Introducir mi tarjeta**.
4. Escribe la tarjeta fila a fila, revísala en la tabla completa y crea el PIN.
5. Exporta una copia de seguridad cuando te lo ofrezca (ver más abajo).

A partir de ahí ya no necesita internet.

## Uso

- **Consultar:** escribe la coordenada y pulsa **Ver** (o Intro). Acepta `C7`, `c7`, `7C`, `C 7` y `J10`. El campo se vacía solo para que puedas pedir otra seguida.
- **Bloqueo:** a los 3 minutos sin tocar la app vuelve a pedir el PIN. También al cerrarla o con el botón **Bloquear**.
- **PIN incorrecto:** a los 5 fallos seguidos se borra la tarjeta del móvil. El contador vuelve a 0 cada vez que aciertas.
- **Menú:** ver o corregir la tarjeta, cambiar el PIN, exportar o restaurar la copia de seguridad, y borrar todo.

## Copia de seguridad

La copia es un archivo `.json` cifrado con el PIN que tenías al exportarlo. Sirve para recuperar la tarjeta si se borran los datos de Chrome, si cambias de móvil o si se activa el borrado por fallos. Para restaurarla, usa **Restaurar copia de seguridad** y escribe el PIN de esa copia.

Guárdala en un sitio que solo controles tú y bórrala de la carpeta Descargas. Fuera de la app no hay límite de 5 intentos (lee la sección de seguridad). Si cambias el PIN, la app te ofrece exportar una copia nueva; las antiguas siguen abriéndose con el PIN antiguo.

## Cómo se protegen los datos

- La clave de cifrado se calcula a partir del PIN con **PBKDF2-SHA256** (600.000 iteraciones y una sal aleatoria). Con ella se cifra la tarjeta con **AES-256-GCM**. El PIN no se guarda: si es incorrecto, el descifrado falla.
- Ese bloque cifrado se vuelve a cifrar con una **segunda clave generada en el propio móvil** que el navegador marca como no exportable. Copiar los datos guardados a otro aparato no basta para descifrarlos.
- La tarjeta descifrada solo existe en memoria mientras la app está desbloqueada, y se descarta al bloquearse.
- El contador de fallos se apunta *antes* de comprobar el PIN, así que cerrar la app a mitad de un intento no lo esquiva.
- La app no se conecta a ningún servidor. Una política de seguridad (CSP) impide cargar o enviar nada fuera de su propia dirección.

**Límites a tener en cuenta:**

- Un PIN de 6 dígitos tiene un millón de combinaciones. Quien consiga **el archivo de copia de seguridad** puede probarlas todas en un ordenador potente en poco tiempo, porque ahí no hay límite de intentos. Por eso la copia hay que guardarla bien.
- La protección del borrado tras 5 fallos depende de que nadie manipule el navegador. El bloqueo de pantalla de tu móvil sigue siendo la primera barrera: mantenlo activado.
- Si el banco y esta app están en el mismo móvil, quien tenga el móvil desbloqueado y tu PIN tiene los dos factores.

## Actualizar la app

Si cambias algún archivo en GitHub, edita `sw.js` y sube el número de `CACHE` (por ejemplo, `tarjeta-v2`). El móvil descargará la versión nueva la próxima vez que abras la app con conexión; puede hacer falta abrirla dos veces. La tarjeta guardada no se pierde.

Los datos están ligados a la dirección de la app. Si cambias el nombre del repositorio o tu usuario, la dirección cambia y tendrás que restaurar la copia de seguridad en la nueva.

## Ajustes

Al principio de `app.js`, en `CONFIG`, puedes cambiar el número de intentos (`MAX_FAILS`) y el tiempo de bloqueo (`LOCK_AFTER_MS`). Si cambias algo, sube también la versión de `CACHE` en `sw.js`.
