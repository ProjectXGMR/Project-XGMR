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
    padding: 40px 20px;
  }

  .profile-card {
    width: 100%;
    max-width: 560px;
    margin: 0 auto;
    background: white;
    border-radius: 24px;
    padding: 36px;
    box-shadow: 0 15px 40px rgba(0, 0, 0, 0.08);
  }

  .avatar {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    background: #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 20px;
    font-size: 44px;
    font-weight: bold;
    color: #4b5563;
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
  }

  h1 {
    text-align: center;
    margin: 0;
    font-size: 30px;
  }

  .username {
    text-align: center;
    color: #6b7280;
    margin-top: 6px;
    margin-bottom: 30px;
  }

  .section {
    margin-top: 24px;
  }

  .section-title {
    font-size: 13px;
    font-weight: bold;
    color: #6b7280;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .bio,
  .interests {
    line-height: 1.7;
    color: #374151;
  }

  .back {
    display: inline-block;
    margin-top: 30px;
    text-decoration: none;
    color: #2563eb;
    font-weight: bold;
  }

  #message {
    text-align: center;
    color: #dc2626;
    margin-top: 20px;
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
const avatar = document.getElementById("appProfileAvatar");

if (profile.avatar_data) {
  avatar.textContent = "";

  const img = document.createElement("img");
  img.src = profile.avatar_data;
  img.alt = "Zdjęcie profilowe";

  img.style.width = "100%";
  img.style.height = "100%";
  img.style.objectFit = "cover";
  img.style.display = "block";

  avatar.innerHTML = "";
  avatar.appendChild(img);
} else {
  avatar.innerHTML = "?";
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

  #authSection,
  #profileSection {
    width: 100%;
    max-width: 520px;
    background: white;
    padding: 32px;
    border-radius: 20px;
    box-shadow: 0 12px 35px rgba(0, 0, 0, 0.08);
  }

  h1,
  h2 {
    text-align: center;
  }

  input,
  textarea {
    width: 100%;
    padding: 12px;
    margin-top: 10px;
    border: 1px solid #d1d5db;
    border-radius: 10px;
    font-size: 15px;
  }

  textarea {
    resize: vertical;
  }

  button {
    width: 100%;
    padding: 12px;
    margin-top: 12px;
    border: none;
    border-radius: 10px;
    background: #2563eb;
    color: white;
    font-size: 15px;
    cursor: pointer;
  }

  button:hover {
    opacity: 0.9;
  }

  hr {
    border: none;
    border-top: 1px solid #e5e7eb;
    margin: 24px 0;
  }

  #authWelcome {
    text-align: center;
  }

  #authWelcome button {
    margin-top: 10px;
  }

  #registerMessage,
  #loginMessage,
  #profileMessage {
    text-align: center;
    margin-top: 15px;
  }
.brand {
  text-align: center;
  margin-bottom: 35px;
}

.brand h1 {
  margin: 0;
  font-size: 42px;
  letter-spacing: -1px;
}

.brand p {
  margin: 8px 0 0;
  color: #6b7280;
  font-size: 16px;
}

.welcome-text {
  text-align: center;
  margin-bottom: 28px;
}

.welcome-text h2 {
  margin-bottom: 8px;
}

.welcome-text p {
  margin: 0;
  color: #6b7280;
  line-height: 1.6;
}

.auth-buttons {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.auth-buttons button {
  margin-top: 8px;
  transition: transform 0.15s ease, opacity 0.15s ease;
}

.auth-buttons button:hover {
  transform: translateY(-1px);
  opacity: 0.9;
}
.dashboard-placeholder {
  margin-top: 25px;
  padding: 20px;
  border-radius: 14px;
  background: #f3f4f6;
  text-align: center;
}

.dashboard-placeholder h3 {
  margin-top: 0;
}

.dashboard-placeholder p {
  color: #6b7280;
  line-height: 1.6;
}
#appSection {
  width: 100%;
  max-width: 1000px;
  background: white;
  border-radius: 20px;
  box-shadow: 0 12px 35px rgba(0, 0, 0, 0.08);
  overflow: hidden;
}

.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px 28px;
  border-bottom: 1px solid #e5e7eb;
}

.app-header h1 {
  margin: 0;
  font-size: 26px;
}

#appUsername {
  color: #6b7280;
}

.app-layout {
  display: flex;
  min-height: 500px;
}

.app-sidebar {
  width: 210px;
  padding: 20px;
  background: #f9fafb;
  border-right: 1px solid #e5e7eb;
}

.app-sidebar button {
  margin-top: 8px;
}

#appLogoutButton {
  margin-top: 35px;
  background: #374151;
}

.app-content {
  flex: 1;
  padding: 35px;
}

.app-content h2 {
  text-align: left;
  margin-top: 0;
}

.app-content p {
  color: #6b7280;
  line-height: 1.6;
}
</style>
</head>

<body>
  <h1>myproject</h1>

<div id="authSection">

  <div id="authWelcome">

    <div class="brand">
      <h1>myproject</h1>
      <p>Twoje miejsce w sieci.</p>
    </div>

    <div class="welcome-text">
      <h2>Witaj!</h2>
      <p>
        Dołącz do myproject lub zaloguj się na swoje konto.
      </p>
    </div>

    <div class="auth-buttons">
      <button id="showRegisterButton" type="button">
        Zarejestruj się
      </button>

      <button id="showLoginButton" type="button">
        Zaloguj się
      </button>
    </div>

  </div>

  <div id="registerSection" style="display:none;">

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

    <button id="backToAuthButton" type="button">
      Wróć
    </button>

  </div>

  <div id="loginSection" style="display:none;">

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

    <button id="backToAuthButtonLogin" type="button">
      Wróć
    </button>

  </div>

</div>
  <div id="loginSection" style="display:none;">

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

    <button id="backToAuthButtonLogin" type="button">
      Wróć
    </button>

  </div>

</div>

<div id="appSection" style="display:none;">

  <div class="app-header">
    <h1>myproject</h1>
    <span id="appUsername"></span>
  </div>

  <div class="app-layout">

    <aside class="app-sidebar">

      <button id="homeButton" type="button">
        Główna
      </button>

      <button id="messagesButton" type="button">
        Wiadomości
      </button>

      <button id="profileButton" type="button">
        Profil
      </button>

      <button id="settingsButton" type="button">
        Ustawienia
      </button>

      <button id="appLogoutButton" type="button">
        Wyloguj
      </button>

    </aside>

    <main class="app-content">

      <div id="homeView">
        <h2>Witaj!</h2>
        <p>
          To jest Twój główny panel myproject.
        </p>
      </div>

      <div id="messagesView" style="display:none;">
        <h2>Wiadomości</h2>
        <p>
          Tutaj pojawią się Twoje rozmowy.
        </p>
      </div>

<div id="profileView" style="display:none;">

  <h2>Twój profil</h2>

  <p>
    <strong>Użytkownik:</strong>
    <span id="appProfileUsername"></span>
  </p>

  <div id="appProfileAvatar"
       style="
         width:120px;
         height:120px;
         margin:20px auto;
         border-radius:50%;
         background:#e5e7eb;
         display:flex;
         align-items:center;
         justify-content:center;
         font-size:40px;
         overflow:hidden;
       ">
    ?
  </div>

  <h3 id="appProfileDisplayName"></h3>

  <p id="appProfileBio">
    Brak opisu.
  </p>

  <p>
    <strong>Zainteresowania:</strong>
    <span id="appProfileInterests">Brak informacji.</span>
  </p>

  <button id="appEditProfileButton" type="button">
    Edytuj profil
  </button>

</div>

      <div id="settingsView" style="display:none;">
        <h2>Ustawienia</h2>
        <p>
          Tutaj pojawią się ustawienia konta.
        </p>
      </div>

    </main>

  </div>

</div>
<div id="profileSection" style="display:none;">

  <hr>

  <h2>Twój profil</h2>

<button id="editProfileButton" type="button">
  Edytuj profil
</button>

  <p><strong>Użytkownik:</strong> <span id="profileUsername"></span></p>

<form id="profileForm" style="display:none;">
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
<button id="cancelEditButton" type="button">
  Anuluj
</button>
 
  </form>

  <p id="profileMessage"></p>

  <button id="logoutButton">Wyloguj się</button>

</div>
  <script>
    const authWelcome = document.getElementById("authWelcome");
const registerSection = document.getElementById("registerSection");
const loginSection = document.getElementById("loginSection");

const showRegisterButton =
  document.getElementById("showRegisterButton");

const showLoginButton =
  document.getElementById("showLoginButton");

const backToAuthButton =
  document.getElementById("backToAuthButton");

const backToAuthButtonLogin =
  document.getElementById("backToAuthButtonLogin");

showRegisterButton.addEventListener("click", () => {
  authWelcome.style.display = "none";
  registerSection.style.display = "block";
  loginSection.style.display = "none";
});

showLoginButton.addEventListener("click", () => {
  authWelcome.style.display = "none";
  registerSection.style.display = "none";
  loginSection.style.display = "block";
});

backToAuthButton.addEventListener("click", () => {
  authWelcome.style.display = "block";
  registerSection.style.display = "none";
  loginSection.style.display = "none";
});

backToAuthButtonLogin.addEventListener("click", () => {
  authWelcome.style.display = "block";
  registerSection.style.display = "none";
  loginSection.style.display = "none";
});
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

if (data.success) {
  loginMessage.textContent = "Zalogowano pomyślnie!";

  document.getElementById("authSection").style.display = "none";
  profileSection.style.display = "none";
  appSection.style.display = "block";

  await loadProfile();

  profileSection.style.display = "none";
} else {
  loginMessage.textContent = data.error;
}

  } catch (error) {
    console.error("Błąd logowania:", error);

    loginMessage.textContent =
      "Wystąpił błąd połączenia.";
  }
});
        const profileSection = document.getElementById("profileSection");
    const appSection = document.getElementById("appSection");
    const profileForm = document.getElementById("profileForm");
    const avatarFile = document.getElementById("avatarFile");
const avatarPreview = document.getElementById("avatarPreview");
let compressedAvatarData = null;

const editProfileButton =
  document.getElementById("editProfileButton");

const cancelEditButton =
  document.getElementById("cancelEditButton");

cancelEditButton.addEventListener("click", () => {
  document.getElementById("displayName").value =
    profileForm.dataset.savedDisplayName || "";

  document.getElementById("bio").value =
    profileForm.dataset.savedBio || "";

  document.getElementById("interests").value =
    profileForm.dataset.savedInterests || "";

  profileForm.style.display = "none";
});

editProfileButton.addEventListener("click", () => {
  profileForm.style.display = "block";
});

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
     
      profileForm.dataset.savedDisplayName =
  data.profile.display_name || "";

profileForm.dataset.savedBio =
  data.profile.bio || "";

profileForm.dataset.savedInterests =
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
 const homeButton = document.getElementById("homeButton");
const messagesButton = document.getElementById("messagesButton");
const profileButton = document.getElementById("profileButton");
const settingsButton = document.getElementById("settingsButton");

const homeView = document.getElementById("homeView");
const messagesView = document.getElementById("messagesView");
const profileView = document.getElementById("profileView");
const settingsView = document.getElementById("settingsView");

function showView(view) {
  homeView.style.display = "none";
  messagesView.style.display = "none";
  profileView.style.display = "none";
  settingsView.style.display = "none";

  view.style.display = "block";
}

homeButton.addEventListener("click", () => {
  showView(homeView);
});

messagesButton.addEventListener("click", () => {
  showView(messagesView);
});

profileButton.addEventListener("click", async () => {
  showView(profileView);
  await loadAppProfile();
});

settingsButton.addEventListener("click", () => {
  showView(settingsView);
});
  async function loadAppProfile() {
  try {
    const response = await fetch("/api/profile");
    const data = await response.json();

    if (!data.success) {
      return;
    }

    const profile = data.profile;
   
    console.log("PROFIL W PANELU:", profile);
console.log("AVATAR DATA:", profile.avatar_data);

alert(
  "avatar_data: " +
  String(profile.avatar_data) +
  "\n\navatar_url: " +
  String(profile.avatar_url)
);
    document.getElementById("appProfileUsername").textContent =
      profile.username || "";

    document.getElementById("appProfileDisplayName").textContent =
      profile.display_name || profile.username || "";

    document.getElementById("appProfileBio").textContent =
      profile.bio || "Brak opisu.";

    document.getElementById("appProfileInterests").textContent =
      profile.interests || "Brak informacji.";

    const avatar = document.getElementById("appProfileAvatar");

    if (profile.avatar_data) {
      avatar.textContent = "";
      avatar.style.backgroundImage =
        "url('" + profile.avatar_data + "')";
      avatar.style.backgroundSize = "cover";
      avatar.style.backgroundPosition = "center";
    } else {
      avatar.style.backgroundImage = "none";
      avatar.textContent = "?";
    }

  } catch (error) {
    console.error("Nie udało się załadować profilu:", error);
  }
}
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
