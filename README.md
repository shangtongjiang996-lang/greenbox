# GreenBox

GreenBox 是一个综合性的在线站点：工具箱、五子棋联机对战、论坛、私信与好友、资源中心、AI 助手，以及一套管理后台。

在线地址：<https://greenboxhweb.com>

## 功能

| 模块 | 说明 |
|---|---|
| 账号 | 注册、登录、会话保持、改密、注销、头像、个人资料 |
| 工具箱 | 后台可上传单文件 HTML 工具，前台按分类展示，支持收藏与搜索 |
| 五子棋 | 创建/加入房间、房间密码、邀请链接、悔棋与重开需对方同意、认输、房间聊天、断线重连、刷新恢复对局 |
| 论坛 | 分类、搜索、排序、发帖（最多 3 图）、评论（最多 2 图）、点赞、收藏、转发、置顶 |
| 私信 / 好友 | 会话列表、消息撤回、置顶、免打扰、好友申请、拉黑、隐私设置、在线状态；支持文本、图片、视频和文件（单文件最大 200MB，附件 7 天后过期） |
| 资源中心 | B2 直传、分片上传、断点续传与暂停/继续、配额管理、视频/音频/图片在线播放、外链资源、管理员上传 |
| AI 助手 | 智谱 GLM 流式对话、深度思考、会话历史、每日次数限制、后台可调模型与提示词 |
| 通知 | 全站广播与定向通知、未读计数 |
| 管理后台 | 工具与更新日志、用户与角色、密码重置、房间管理、AI 配置与配额、通知群发 |

## 技术栈

- 后端：Node.js 18+、Express 4、Socket.IO 4
- 存储：Redis（ioredis，业务数据以 JSON 形式保存）、Backblaze B2（S3 兼容对象存储）
- AI：智谱 GLM（`glm-4-flash`），服务端 SSE 转发
- 前端：原生 HTML / CSS / JavaScript，无框架，单 `style.css` 支持明暗主题与响应式
- 部署：Render Web Service

## 目录结构

```text
greenbox-realtime/
├── app.js                  # 主服务：鉴权、工具、资源、AI、通知、后台、论坛、五子棋
├── social.js               # 私信、好友、隐私设置、论坛收藏与转发
├── redis.js                # Redis KV 适配层
├── package.json
├── railway.toml            # 早期 Railway 配置，Render 不使用，可删除
├── public/                 # 静态页面，由 Express 直接托管
│   ├── index.html          # 首页与 AI 助手
│   ├── tools.html
│   ├── changelog.html
│   ├── forum.html
│   ├── messages.html
│   ├── resources.html
│   ├── gomoku-online.html
│   ├── profile.html
│   ├── user.html
│   ├── admin.html
│   ├── login.html
│   ├── register.html
│   ├── other.html          # 其它：关于、常用入口、帮助
│   ├── function-plotter.html
│   ├── style.css
│   ├── script.js
│   ├── icons.svg
│   └── data.json
└── scripts/
    └── cleanup-legacy-password.js   # 一次性迁移脚本
```

## 快速开始

要求 Node.js 18 及以上，准备一个 Redis 实例。资源中心与 AI 助手需要额外配置，不配置时对应功能不可用，其余功能可正常运行。

```bash
git clone https://github.com/shangtongjiang996-lang/greenbox.git
cd greenbox
npm install
npm start
```

默认监听 `http://localhost:3000`。

### 环境变量

在项目根目录创建 `.env`，或直接在部署平台的环境变量里配置：

```dotenv
PORT=3000
REDIS_URL=redis://default:password@host:6379

# 管理员初始密码，首次登录后请在后台修改
ADMIN=change-me

# 智谱 AI，缺失时 /api/chat/stream 返回 503
ZHIPU_API_KEY=

# Backblaze B2 对象存储
B2_ENDPOINT=s3.us-east-005.backblazeb2.com
B2_REGION=us-east-005
B2_BUCKET_NAME=
B2_KEY_ID=
B2_APP_KEY=
```

| 变量 | 必填 | 说明 |
|---|---|---|
| `PORT` | 否 | 监听端口，默认 `3000` |
| `REDIS_URL` | 是 | Redis 连接串 |
| `ADMIN` | 是 | 管理员初始密码，登录后在后台修改 |
| `ZHIPU_API_KEY` | 否 | 不配置时 AI 接口返回 503 |
| `B2_*` | 否 | 不配置时资源中心上传不可用 |

不要把 `.env` 提交到仓库，也不要把密钥写进源码。

## 部署

以 Render 为例：

- 类型：Web Service
- Build Command：`npm install`
- Start Command：`npm start`
- 环境变量：参考上表，`PORT` 由平台注入

说明：

- 静态文件由 Express 托管，目录固定为 `public/`，不需要单独配置静态站点。
- 房间状态和在线状态保存在进程内存与 Redis 中。当前实现按单实例设计；如果需要多实例，需增加 Socket.IO Redis Adapter 和粘性会话。
- 建议为 Redis 开启持久化，避免重启后会话与业务数据丢失。
- `railway.toml` 是早期部署配置，Render 不会读取，可以删除。

## 主要接口

所有需要登录的接口使用 `Authorization: Bearer <token>`。

| 分类 | 路径 |
|---|---|
| 账号 | `POST /api/register`、`POST /api/login`、`GET /api/verify`、`POST /api/logout`、`POST /api/change-my-password` |
| 用户 | `GET /api/user/me`、`PUT /api/user/profile`、`POST /api/user/avatar`、`GET /api/user/avatar/:username` |
| 工具 | `GET /api/data`、`POST /api/tool/upload`、`GET /tool/:id` |
| 五子棋 | `POST /api/room/create`、`/api/room/join`、`/api/room/leave`、`/api/room/heartbeat`、`GET /api/rooms`、`GET /api/room/:roomId` |
| 论坛 | `GET /api/forum/posts`、`GET /api/forum/posts/:id`、`POST /api/forum/posts`、`POST /api/forum/posts/:id/comments`、`POST /api/forum/posts/:id/like` |
| 资源 | `POST /api/resource/upload-url`、`POST /api/resource/confirm`、`GET /api/resource/list/:category`、`GET /api/resource/quota`、`DELETE /api/resource/:id` |
| 资源分片 | `POST /api/resource/multipart/create`、`POST /api/resource/multipart/part-url`、`GET /api/resource/multipart/status`、`POST /api/resource/multipart/complete`、`POST /api/resource/multipart/abort` |
| 私信附件 | `POST /api/dm/upload-url`、`GET /api/dm/attachment/:convId/:msgId` |
| AI | `GET /api/chat/config`、`GET /api/chat/quota`、`GET/POST /api/chat/sessions`、`POST /api/chat/stream` |
| 通知 | `GET /api/notifications`、`POST /api/notifications/read`、`GET /api/notifications/unread-count` |
| 后台 | `/api/admin/*`，均需管理员会话 |

Socket.IO 事件：

- 五子棋：`join-room`、`make-move`、`undo-request`、`restart-request`、`respond-request`、`resign`、`send-message`
- 服务端推送：`joined`、`room-update`、`request`、`request-result`、`request-cancel`、`new-message`、`room-closed`、`notice`、`error`
- 私信：`dm:auth`、`dm:send`、`dm:typing`、`dm:read`、`dm:recall`

## 数据说明

Redis 中按前缀保存业务数据：

- `users`、`session:*`、`user_profile:*`、`user_avatar:*`
- `gomoku:*`：房间状态、棋盘、聊天记录
- `forum_*`：帖子、评论、索引、积分、收藏
- `resource:*`、`resource_index:*`：资源记录与分类索引
- `chat_*`：AI 会话、配额、配置
- `dm_*`、`friends:*`、`friend_requests*`：私信与好友

资源文件保存在 B2，Redis 只存对象 key。资源列表在每次读取时会重新生成 7 天有效的预签名链接，因此历史资源不会因为链接过期而失效。

私信附件同样存放在 B2（`dm/<用户名>/...`），Redis 只保存文件名、大小、类型和过期时间。附件默认 7 天有效，过期后接口返回 410，并在读取时尽力删除对应对象。

资源中心的大文件使用 S3 分片上传：每片 8MB，单文件最大 2GB，普通用户仍受 50MB 总配额限制。上传进度保存在浏览器本地，网络中断或刷新页面后可以重新选择同一个文件继续，未完成的分片会保留在 B2，直到合并或主动放弃。

## 迁移脚本

如果是从旧版本升级，历史用户记录里可能残留可逆加密的密码字段。部署完成后执行一次：

```bash
node scripts/cleanup-legacy-password.js
```

脚本只删除遗留字段，不影响登录。建议在低峰期运行。

## 许可

本项目未声明开源许可证，默认保留所有权利。
