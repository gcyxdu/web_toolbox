# 任务：把重启后停掉的两套 Windows 演示拉起来

给 Codex。只做这一张。做完停下来，写一份结果说明。不要自行扩大范围。

## 背景

工作目录是 `d:\联合成果展示`。联合成果是一个入口页加两套系统，各模块保持原来的程序，不要合成一个工程。

2026-11-02 核对过端口：

- `http://127.0.0.1:8000/` VisualFL 正在运行。不要重启、不要关掉。
- `http://127.0.0.1:8090/` 入口页正在运行。不要重启这个 Python 进程。可以改 `portal\index.html`，静态文件会直接生效。
- `127.0.0.1:8352` 脱敏系统没在听。
- `127.0.0.1:3306` MySQL 没在听。
- SGBoost 的 2020 / 2021 / 2023 / 8123 没在听。这些端口是连上就关，不能只用「端口是否一直监听」判断进程是否还活着，要看进程和日志。

入口页上 SGBoost 和脱敏发布已经标成「重启后未启动」。拉起来并确认可访问之后，再改回「本机运行中」。没确认成功就不要改成运行中。

## 要做的事

### 1. 启动 MySQL，再启动脱敏系统

- MySQL 程序：`D:\local-runtime\mysql-8.0.29-winx64`
- 数据目录：`D:\local-runtime\mysql-data`
- 配置：`D:\local-runtime\mysql-8.0.29-winx64\my.ini`
- 客户端配置：`D:\local-runtime\mysql-client.cnf`（密码在这个文件里。不要把密码写进入口页、任务说明或任何新建文档）
- 只绑定 `127.0.0.1:3306`。如果已经有 mysqld 在听 3306，就复用，不要再起一个。
- 脱敏用 Temurin 8：`D:\local-runtime\jdk\jdk8u504-b01\bin\java.exe`
- 工作目录必须是 `E:\2.6项目数据备份\系统代码\DesenTelecom`
- 启动：`java -jar gademo0311Feng.jar`
- 这个 jar 约 1GB，启动要几十秒。完成后请求 `http://127.0.0.1:8352/`，确认 HTTP 200，页面标题里能看到脱敏相关字样。
- 不要安装 Miniconda，不要创建名为 `torch_env` 的环境。脱敏程序如果发现这个环境名，会改去调用它。
- 图像、音频脚本用系统 Python：`C:\Program Files\Python312\python.exe`。不要改这个 Python 里的 torch。

### 2. 按顺序启动 SGBoost 的三个训练进程

- Java 必须用 `D:\PyCharm\PyCharm 2026.2.1\jbr\bin\java.exe`。系统里的 Java 8 跑不了这个 jar（字节码是 Java 12）。
- 工作目录：`C:\SGBoost`
- 命令形如：`java -cp C:\SGBoost\SGBoost.jar <类名>`
- 启动顺序，每个间隔约 2 秒：
  1. `cloud.CloudServiceProvider`
  2. `dataowner.DataOrganizer`
  3. `dataowner.DataOwner`
- 标准输出和错误写到 `d:\联合成果展示\runtime-logs\`，文件名带上类名，避免覆盖旧日志。日志是 GBK。
- 先看这三个类是不是已经在跑。已经在跑就不要再起一套。
- 不要启动 `user.user`。推理客户端要等模型发布之后再开。`scripts\start-sgboost-user.bat` 这次不要运行。
- 验收看日志里出现 CSP 初始化、Organizer 在 `127.0.0.1:8123`、以及和数据方交换加密参数。只看到进程还在、日志没有这些内容，不算完成。

### 3. 改入口页，让文字和实际状态一致

文件：`d:\联合成果展示\portal\index.html`

- 脱敏：8352 返回 200 之后，把卡片改回「本机运行中」，保留「打开脱敏系统」按钮，指向 `http://127.0.0.1:8352/`。
- SGBoost：三个进程的日志确认初始化之后，把卡片改回「本机运行中」，写明日志目录。不要写一个打不开的网页按钮，这个程序没有网页。
- 页头那句「重启后已停」按结果改。哪套没起来，哪套就继续写未启动，并写上失败原因。
- 不要改 VisualFL、Kangaroo、工具集四张卡片的技术结论。

## 不要做

- 不要 `git commit`，不要改 git config。
- 不要重启电脑，不要安装 Ubuntu / WSL 发行版。
- 不要编译 Kangaroo、OpenHiTLS、PQCP、字节工具集、seccom-tee、PIANO。
- 不要安装 secretflow。
- 不要编造采集页面。脱敏系统没有这个菜单。
- 不要把 `modules\seccom-tee` 写成刘睿康的项目。seccom-tee 是何琪 / openEuler。刘睿康在工具集里对应的是 PQCP。原理验证里的「TEE + 可验证」没有单独仓库。
- 不要把 VisualFL 写成 TEE 或多方隐私协议。它是明文在线联邦学习实验台。
- 不要声称这台 i7-12700 能加载真 SGX enclave。
- 不要删 `modules\` 里的源码，不要动 `E:\2.6项目数据备份` 里的原始 jar 和 SQL。

## 做完交什么

用简体中文写一段结果，放在本次回复里，不要另建总结文件。包含：

- MySQL 是否在 3306，脱敏首页是否 200。
- SGBoost 三个进程的进程号，以及日志里能证明它们已经接上的原句。
- 入口页改了哪几句。
- 没做成的部分和报错原文。
