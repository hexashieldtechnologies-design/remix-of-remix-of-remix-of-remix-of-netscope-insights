const { contextBridge } = require("electron");
contextBridge.exposeInMainWorld("netscope", {
  platform: process.platform,
  isDesktop: true,
  versions: { electron: process.versions.electron, chrome: process.versions.chrome },
});
