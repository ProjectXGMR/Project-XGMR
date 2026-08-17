const PASSWORD_ITERATIONS = 100000;
const SESSION_DAYS = 7;

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: extraHeaders
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${PASSWORD_ITERATIONS}$${bytesToHex(salt)}$${bytesToHex(
    new Uint8Array(derivedBits)
  )}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash.startsWith("pbkdf2$")) {
    const oldHash = bytesToHex(await sha256(password));
    return oldHash === storedHash;
  }

  const parts = storedHash.split("$");

  if (parts.length !== 4) {
    return false;
  }

  const iterations = Number(parts[1]);
  const salt = hexToBytes(parts[2]);
  const expected = hexToBytes(parts[3]);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  const actual = new Uint8Array(derivedBits);

  if (actual.length !== expected.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < actual.length; i++) {
    difference |= actual[i] ^ expected[i];
  }

  return difference === 0;
}

async function createSession(env, userId) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToHex(tokenBytes);
  const tokenHash = bytesToHex(await sha256(token));

  const expiresAt = new Date(
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB
    .prepare(
      "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
    )
    .bind(userId, tokenHash, expiresAt)
    .run();

  return token;
}

function sessionCookie(token) {
  return [
    `session=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
  ].join("; ");
}

async function getCurrentUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

  if (!match) {
    return null;
  }

  const token = match[1];
  const tokenHash = bytesToHex(await sha256(token));

  return await env.DB
    .prepare(
      `SELECT
        users.id,
        users.username,
        users.email,
        profiles.display_name,
        profiles.bio,
        profiles.interests,
        profiles.avatar_url
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      LEFT JOIN profiles ON profiles.user_id = users.id
      WHERE sessions.token_hash = ?
        AND sessions.expires_at > CURRENT_TIMESTAMP`
    )
    .bind(tokenHash)
    .first();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Publiczna strona profilu
if (
  url.pathname.startsWith("/u/") &&
  request.method === "GET"
) {
  const username = decodeURIComponent(
    url.pathname.substring("/u/".length)
  ).trim();

  if (!username) {
    return new Response("Nie podano użytkownika.", {
      status: 400,
      headers: {
        "Content-Type": "text/plain; charset=UTF-8"
      }
    });
  }

  return new Response(
    `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Profil - ${username}</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: Arial, sans-serif;
      background: #f3f4f6;
      color: #111827;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 24px;
    }

    .profile-card {
      width: 100%;
      max-width: 520px;
      background: white;
      border-radius: 18px;
      padding: 32px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
    }

    .avatar {
      width: 96px;
      height: 96px;
      border-radius: 50%;
      background: #e5e7eb;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 20px;
      font-size: 38px;
      font-weight: bold;
      color: #4b5563;
    }

    h1 {
      text-align: center;
      margin: 0 0 6px;
    }

    .username {
      text-align: center;
      color: #6b7280;
      margin-bottom: 28px;
    }

    .section {
      margin-top: 20px;
    }

    .section-title {
      font-size: 14px;
      font-weight: bold;
      color: #6b7280;
      margin-bottom: 6px;
      text-transform: uppercase;
    }

    .bio {
      line-height: 1.6;
    }

    .interests {
      line-height: 1.6;
    }

    .back {
      display: inline-block;
      margin-top: 28px;
      text-decoration: none;
      color: #2563eb;
    }

    #message {
      text-align: center;
      color: #dc2626;
    }
  </style>
</head>

<body>
  <main class="profile-card">

    <div class="avatar" id="avatar">
      ?
    </div>

    <h1 id="displayName">Ładowanie profilu...</h1>

    <div class="username">
      @<span id="username"></span>
    </div>

    <div class="section">
      <div class="section-title">O mnie</div>
      <div class="bio" id="bio"></div>
    </div>

    <div class="section">
      <div class="section-title">Zainteresowania</div>
      <div class="interests" id="interests"></div>
    </div>

    <p id="message"></p>

    <a class="back" href="/">← Wróć na stronę główną</a>

  </main>

  <script>
    async function loadPublicProfile() {
      try {
        const response = await fetch(
          "/api/users/" + encodeURIComponent(${JSON.stringify(username)})
        );

        const data = await response.json();

        if (!data.success) {
          document.getElementById("message").textContent =
            data.error || "Nie znaleziono profilu.";
          return;
        }

        document.getElementById("displayName").textContent =
          data.profile.display_name || data.profile.username;
          const avatar = document.getElementById("avatar");

if (data.profile.avatar_data) {
  avatar.textContent = "";
  avatar.style.backgroundImage =
    "url('" + data.profile.avatar_data + "')";
  avatar.style.backgroundSize = "cover";
  avatar.style.backgroundPosition = "center";
} else {
  avatar.textContent = "?";
}

        document.getElementById("username").textContent =
          data.profile.username;

        document.getElementById("bio").textContent =
          data.profile.bio || "Brak opisu.";

        document.getElementById("interests").textContent =
          data.profile.interests || "Brak informacji.";
      } catch (error) {
        document.getElementById("message").textContent =
          "Nie udało się pobrać profilu.";
      }
    }

    loadPublicProfile();
  </script>
</body>
</html>`,
    {
      headers: {
        "Content-Type": "text/html; charset=UTF-8"
      }
    }
  );
}
    // Strona główna
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(
        `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>myproject</title>
</head>

<body>
  <h1>myproject</h1>

  <h2>Utwórz konto</h2>

  <form id="registerForm">
    <input
      type="text"
      id="registerUsername"
      placeholder="Nazwa użytkownika"
      required
    >

    <input
      type="email"
      id="registerEmail"
      placeholder="E-mail"
      required
    >

    <input
      type="password"
      id="registerPassword"
      placeholder="Hasło"
      required
    >

    <button type="submit">Zarejestruj się</button>
  </form>

  <p id="registerMessage"></p>

  <hr>

  <h2>Zaloguj się</h2>

  <form id="loginForm">
    <input
      type="email"
      id="loginEmail"
      placeholder="E-mail"
      required
    >

    <input
      type="password"
      id="loginPassword"
      placeholder="Hasło"
      required
    >

    <button type="submit">Zaloguj się</button>
  </form>

  <p id="loginMessage"></p>
<div id="profileSection" style="display:none;">

  <hr>

  <h2>Twój profil</h2>

  <p><strong>Użytkownik:</strong> <span id="profileUsername"></span></p>

  <form id="profileForm">
<label for="avatarFile">Zdjęcie profilowe</label>

<br>

<input
  type="file"
  id="avatarFile"
  accept="image/jpeg,image/png,image/webp"
>

<br><br>

<img
  id="avatarPreview"
  alt="Podgląd zdjęcia profilowego"
  style="display:none; width:120px; height:120px; object-fit:cover; border-radius:50%;"
>
    <input
      type="text"
      id="displayName"
      placeholder="Nazwa wyświetlana"
      required
    >

    <br><br>

    <textarea
      id="bio"
      placeholder="Opowiedz coś o sobie"
      rows="5"
    ></textarea>

    <br><br>

    <input
      type="text"
      id="interests"
      placeholder="Zainteresowania"
    >

    <br><br>

    <button type="submit">Zapisz profil</button>

  </form>

  <p id="profileMessage"></p>

  <button id="logoutButton">Wyloguj się</button>

</div>
  <script>
    const registerForm = document.getElementById("registerForm");
    const registerMessage = document.getElementById("registerMessage");

    registerForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      registerMessage.textContent = "Tworzenie konta...";

      try {
        const response = await fetch("/api/register", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            username: document.getElementById("registerUsername").value,
            email: document.getElementById("registerEmail").value,
            password: document.getElementById("registerPassword").value
          })
        });

        const data = await response.json();

        registerMessage.textContent = data.success
          ? "Konto zostało utworzone!"
          : data.error;
      } catch (error) {
        registerMessage.textContent =
          "Wystąpił błąd połączenia.";
      }
    });

    const loginForm = document.getElementById("loginForm");
    const loginMessage = document.getElementById("loginMessage");

    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      loginMessage.textContent = "Logowanie...";

      try {
        const response = await fetch("/api/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            email: document.getElementById("loginEmail").value,
            password: document.getElementById("loginPassword").value
          })
        });

        const data = await response.json();

        loginMessage.textContent = data.success
          ? "Zalogowano pomyślnie!"
          : data.error;
      } catch (error) {
        loginMessage.textContent =
          "Wystąpił błąd połączenia.";
      }
        const profileSection = document.getElementById("profileSection");
    const profileForm = document.getElementById("profileForm");
    const avatarFile = document.getElementById("avatarFile");
const avatarPreview = document.getElementById("avatarPreview");
let compressedAvatarData = null;

avatarFile.addEventListener("change", async () => {
  const file = avatarFile.files[0];

  if (!file) {
    avatarPreview.style.display = "none";
    avatarPreview.src = "";
    return;
  }

  if (!file.type.startsWith("image/")) {
    avatarFile.value = "";
    avatarPreview.style.display = "none";
    avatarPreview.src = "";
    profileMessage.textContent = "Wybierz plik graficzny.";
    return;
  }

  try {
    const image = new Image();

    const imageUrl = URL.createObjectURL(file);

    image.onload = async () => {
      URL.revokeObjectURL(imageUrl);

      const canvas = document.createElement("canvas");
      const maxSize = 256;

      let width = image.width;
      let height = image.height;

      if (width > height) {
        if (width > maxSize) {
          height = Math.round(height * maxSize / width);
          width = maxSize;
        }
      } else {
        if (height > maxSize) {
          width = Math.round(width * maxSize / height);
          height = maxSize;
        }
      }

      canvas.width = width;
      canvas.height = height;

      const context = canvas.getContext("2d");

      context.drawImage(image, 0, 0, width, height);

      let quality = 0.85;
      let compressedData = canvas.toDataURL("image/jpeg", quality);

      while (
        compressedData.length > 260000 &&
        quality > 0.2
      ) {
        quality -= 0.05;
        compressedData = canvas.toDataURL("image/jpeg", quality);
      }

compressedAvatarData = compressedData;

avatarPreview.src = compressedData;
avatarPreview.style.display = "block";

      profileMessage.textContent =
        "Zdjęcie zostało automatycznie zmniejszone.";
    };

    image.src = imageUrl;
  } catch (error) {
    avatarFile.value = "";
    avatarPreview.style.display = "none";
    avatarPreview.src = "";
    profileMessage.textContent =
      "Nie udało się przetworzyć zdjęcia.";
  }
});
    const profileMessage = document.getElementById("profileMessage");
    const logoutButton = document.getElementById("logoutButton");

    async function loadProfile() {
      try {
        const response = await fetch("/api/profile");
        const data = await response.json();

        if (!data.success) {
          profileSection.style.display = "none";
          return;
        }

        profileSection.style.display = "block";

        document.getElementById("profileUsername").textContent =
          data.profile.username;

        document.getElementById("displayName").value =
          data.profile.display_name || "";

        document.getElementById("bio").value =
          data.profile.bio || "";

        document.getElementById("interests").value =
          data.profile.interests || "";
      } catch (error) {
        profileSection.style.display = "none";
      }
    }

    profileForm.addEventListener("submit", async (event) => {
      event.preventDefault();

profileMessage.textContent = compressedAvatarData
  ? "TEST: avatar jest w pamięci"
  : "TEST: avatar jest pusty";

      try {
      console.log("AVATAR PRZED WYSŁANIEM:", compressedAvatarData);

       if (!compressedAvatarData) {
  profileMessage.textContent = "TEST: avatar jest pusty";
} else {
  profileMessage.textContent =
    "TEST: avatar jest w pamięci (" +
    Math.round(compressedAvatarData.length / 1024) +
    " KB)";
}
        
        const response = await fetch("/api/profile", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json"
          },
body: JSON.stringify({
  display_name: document.getElementById("displayName").value,
  bio: document.getElementById("bio").value,
  interests: document.getElementById("interests").value,
  avatar_data: compressedAvatarData
})
        });

        const data = await response.json();

        profileMessage.textContent = data.success
          ? "Profil został zapisany!"
          : data.error;

        if (data.success) {
          await loadProfile();
        }
      } catch (error) {
        profileMessage.textContent =
          "Wystąpił błąd połączenia.";
      }
    });

    logoutButton.addEventListener("click", async () => {
      const response = await fetch("/api/logout", {
        method: "POST"
      });

      const data = await response.json();

      if (data.success) {
        profileSection.style.display = "none";
        loginMessage.textContent = "Wylogowano.";
      }
    });

    loadProfile();
    });
  </script>
</body>
</html>`,
        {
          headers: {
            "Content-Type": "text/html; charset=UTF-8"
          }
        }
      );
    }

    // Rejestracja
    if (url.pathname === "/api/register" && request.method === "POST") {
      try {
        const data = await request.json();

        const username = String(data.username || "").trim();
        const email = String(data.email || "").trim().toLowerCase();
        const password = String(data.password || "");

        if (!username || !email || !password) {
          return json(
            {
              success: false,
              error: "Wszystkie pola są wymagane."
            },
            400
          );
        }

        if (password.length < 8) {
          return json(
            {
              success: false,
              error: "Hasło musi mieć co najmniej 8 znaków."
            },
            400
          );
        }

        const existingUser = await env.DB
          .prepare(
            "SELECT id FROM users WHERE username = ? OR email = ?"
          )
          .bind(username, email)
          .first();

        if (existingUser) {
          return json(
            {
              success: false,
              error: "Użytkownik lub e-mail już istnieje."
            },
            409
          );
        }

        const passwordHash = await createPasswordHash(password);

        const result = await env.DB
          .prepare(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
          )
          .bind(username, email, passwordHash)
          .run();

        const userId = result.meta.last_row_id;

        await env.DB
          .prepare(
            "INSERT INTO profiles (user_id, display_name) VALUES (?, ?)"
          )
          .bind(userId, username)
          .run();

        return json({
          success: true,
          message: "Konto zostało utworzone.",
          user: {
            id: userId,
            username,
            email
          }
        });
      } catch (error) {
        return json(
          {
            success: false,
            error: "Nie udało się utworzyć konta."
          },
          500
        );
      }
    }

    // Logowanie
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const data = await request.json();

        const email = String(data.email || "").trim().toLowerCase();
        const password = String(data.password || "");

        if (!email || !password) {
          return json(
            {
              success: false,
              error: "E-mail i hasło są wymagane."
            },
            400
          );
        }

        const user = await env.DB
          .prepare(
            "SELECT id, username, email, password_hash FROM users WHERE email = ?"
          )
          .bind(email)
          .first();

        if (!user) {
          return json(
            {
              success: false,
              error: "Nieprawidłowy e-mail lub hasło."
            },
            401
          );
        }

        const validPassword = await verifyPassword(
          password,
          user.password_hash
        );

        if (!validPassword) {
          return json(
            {
              success: false,
              error: "Nieprawidłowy e-mail lub hasło."
            },
            401
          );
        }

        // Jeśli konto ma jeszcze stary SHA-256,
        // po poprawnym logowaniu automatycznie przechodzimy
        // na PBKDF2.
        if (!user.password_hash.startsWith("pbkdf2$")) {
          const newPasswordHash = await createPasswordHash(password);

          await env.DB
            .prepare(
              "UPDATE users SET password_hash = ? WHERE id = ?"
            )
            .bind(newPasswordHash, user.id)
            .run();
        }

        const token = await createSession(env, user.id);

        return json(
          {
            success: true,
            message: "Zalogowano pomyślnie.",
            user: {
              id: user.id,
              username: user.username,
              email: user.email
            }
          },
          200,
          {
            "Set-Cookie": sessionCookie(token)
          }
        );
      } catch (error) {
        return json(
          {
            success: false,
            error: "Nie udało się zalogować."
          },
          500
        );
      }
    }

        // Pobieranie profilu
    if (url.pathname === "/api/profile" && request.method === "GET") {
      const user = await getCurrentUser(request, env);

      if (!user) {
        return json(
          {
            success: false,
            error: "Musisz być zalogowany."
          },
          401
        );
      }

      return json({
        success: true,
        profile: {
          username: user.username,
          display_name: user.display_name,
          bio: user.bio,
          interests: user.interests,
          avatar_url: user.avatar_url
        }
      });
    }

    // Aktualizacja profilu
    if (url.pathname === "/api/profile" && request.method === "PUT") {
      try {
        const user = await getCurrentUser(request, env);

        if (!user) {
          return json(
            {
              success: false,
              error: "Musisz być zalogowany."
            },
            401
          );
        }

        const data = await request.json();

        const displayName = String(data.display_name || "").trim();
        const bio = String(data.bio || "").trim();
        const interests = String(data.interests || "").trim();
        const avatarData = data.avatar_data || null;

        if (!displayName) {
          return json(
            {
              success: false,
              error: "Nazwa wyświetlana jest wymagana."
            },
            400
          );
        }

        await env.DB
       await env.DB
  .prepare(
    `UPDATE profiles
     SET display_name = ?,
         bio = ?,
         interests = ?,
         avatar_data = ?,
         updated_at = CURRENT_TIMESTAMP
     WHERE user_id = ?`
  )
  .bind(
    displayName,
    bio,
    interests,
    avatarData,
    user.id
  )
  .run();

        return json({
          success: true,
          message: "Profil został zaktualizowany."
        });
      } catch (error) {
        return json(
          {
            success: false,
            error: "Nie udało się zaktualizować profilu."
          },
          500
        );
      }
    }
    // Publiczny profil użytkownika
if (url.pathname.startsWith("/api/users/") && request.method === "GET") {
  try {
    const username = decodeURIComponent(
      url.pathname.substring("/api/users/".length)
    ).trim();

    if (!username) {
      return json(
        {
          success: false,
          error: "Nie podano użytkownika."
        },
        400
      );
    }

    const user = await env.DB
      .prepare(
 `SELECT
  users.username,
  profiles.display_name,
  profiles.bio,
  profiles.interests,
  profiles.avatar_url,
  profiles.avatar_data
        FROM users
        LEFT JOIN profiles ON profiles.user_id = users.id
        WHERE users.username = ?`
      )
      .bind(username)
      .first();

    if (!user) {
      return json(
        {
          success: false,
          error: "Nie znaleziono użytkownika."
        },
        404
      );
    }

return json({
  success: true,
  profile: {
    username: user.username,
    display_name: user.display_name,
    bio: user.bio,
    interests: user.interests,
    avatar_url: user.avatar_url,
    avatar_data: user.avatar_data
  }
});
  } catch (error) {
    return json(
      {
        success: false,
        error: "Nie udało się pobrać profilu."
      },
      500
    );
  }
}
             // Publiczny profil użytkownika
    if (url.pathname.startsWith("/api/users/") && request.method === "GET") {
      try {
        const username = decodeURIComponent(
          url.pathname.substring("/api/users/".length)
        ).trim();

        if (!username) {
          return json(
            {
              success: false,
              error: "Nie podano użytkownika."
            },
            400
          );
        }

        const user = await env.DB
          .prepare(
            `SELECT
              users.username,
              profiles.display_name,
              profiles.bio,
              profiles.interests,
              profiles.avatar_url
            FROM users
            LEFT JOIN profiles ON profiles.user_id = users.id
            WHERE users.username = ?`
          )
          .bind(username)
          .first();

        if (!user) {
          return json(
            {
              success: false,
              error: "Nie znaleziono użytkownika."
            },
            404
          );
        }

        return json({
          success: true,
          profile: {
            username: user.username,
            display_name: user.display_name,
            bio: user.bio,
            interests: user.interests,
            avatar_url: user.avatar_url
          }
        });
      } catch (error) {
        return json(
          {
            success: false,
            error: "Nie udało się pobrać profilu."
          },
          500
        );
      }
    }
    // Sprawdzenie aktualnej sesji
    if (url.pathname === "/api/me" && request.method === "GET") {
      const user = await getCurrentUser(request, env);

      if (!user) {
        return json(
          {
            success: false,
            authenticated: false
          },
          401
        );
      }

      return json({
        success: true,
        authenticated: true,
        user
      });
    }

    // Wylogowanie
    if (url.pathname === "/api/logout" && request.method === "POST") {
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

      if (match) {
        const tokenHash = bytesToHex(await sha256(match[1]));

        await env.DB
          .prepare("DELETE FROM sessions WHERE token_hash = ?")
          .bind(tokenHash)
          .run();
      }

      return json(
        {
          success: true,
          message: "Wylogowano."
        },
        200,
        {
          "Set-Cookie":
            "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        }
      );
    }

    return json(
      {
        success: false,
        error: "Nie znaleziono strony."
      },
      404
    );
  }
};
