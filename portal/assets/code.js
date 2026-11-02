const NAMES = {
  sgboost: "SGBoost",
  kangaroo: "Kangaroo",
  byte: "字节",
  ttsdc: "TTSDC",
  "seccom-tee": "seccom-tee",
  pqcp: "PQCP",
};

const id = new URLSearchParams(location.search).get("id") || "";
const title = NAMES[id] || "源码";
document.title = title;

const treeEl = document.getElementById("tree");
const nameEl = document.getElementById("name");
const codeEl = document.getElementById("code");

async function list(path) {
  const url = "/api/list?id=" + encodeURIComponent(id) + "&path=" + encodeURIComponent(path);
  const res = await fetch(url);
  if (!res.ok) throw new Error("list");
  return res.json();
}

async function openFile(path) {
  nameEl.textContent = title + " / " + path.replace(/\\/g, "/");
  codeEl.textContent = "";
  const url = "/api/file?id=" + encodeURIComponent(id) + "&path=" + encodeURIComponent(path);
  const res = await fetch(url);
  codeEl.textContent = await res.text();
  treeEl.querySelectorAll(".file").forEach((n) => {
    n.classList.toggle("is-on", n.dataset.path === path);
  });
}

function join(base, name) {
  return base ? base + "/" + name : name;
}

async function mount(parent, path, depth) {
  const data = await list(path);
  for (const dir of data.dirs) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "node dir";
    row.style.paddingLeft = 12 + depth * 14 + "px";
    row.textContent = dir;
    const kids = document.createElement("div");
    kids.hidden = true;
    let loaded = false;
    row.addEventListener("click", async () => {
      kids.hidden = !kids.hidden;
      row.classList.toggle("open", !kids.hidden);
      if (!loaded) {
        loaded = true;
        try {
          await mount(kids, join(path, dir), depth + 1);
        } catch (err) {
          kids.textContent = "无法读取";
        }
      }
    });
    parent.append(row, kids);
  }
  for (const file of data.files) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "node file";
    row.style.paddingLeft = 12 + depth * 14 + "px";
    row.textContent = file;
    row.dataset.path = join(path, file);
    row.addEventListener("click", () => openFile(row.dataset.path));
    parent.append(row);
  }
  return data;
}

(async function init() {
  if (!NAMES[id]) {
    nameEl.textContent = "";
    codeEl.textContent = "没有这个模块。";
    return;
  }
  try {
    const data = await mount(treeEl, "", 0);
    const prefer = ["README.md", "README", "readme.md", "CMakeLists.txt", "Makefile"];
    const hit = prefer.find((n) => data.files.includes(n));
    if (hit) await openFile(hit);
    else if (data.files[0]) await openFile(data.files[0]);
    else nameEl.textContent = title;
  } catch (err) {
    codeEl.textContent = "源码服务未启动，请重新打开入口页。";
  }
})();
