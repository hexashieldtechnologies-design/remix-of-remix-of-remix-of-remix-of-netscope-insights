// NetScope Electron main process.
// Loads the NetScope web app (published URL or local dev server) in a hardened window.
const { app, BrowserWindow, shell } = require("electron");
const path = require("path");

const APP_URL = process.env.NETSCOPE_URL || "http://localhost:8080";

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#14191f",
    title: "NetScope",
    icon: path.join(__dirname, "..", "public", "icon-512.png"),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadURL(APP_URL);
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => BrowserWindow.getAllWindows().length === 0 && createWindow());
});
app.on("window-all-closed", () => process.platform !== "darwin" && app.quit());
