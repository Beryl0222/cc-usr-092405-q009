# 光动力早期试验

管理局部不可切除胰腺肿瘤光动力早期试验的受控流程：方案版本与安全委员会（DSMB）放行、
中心资质、受试者同意与入排、药物/器械批次、剂量队列、给药→照光操作时间线、
紧急偏离与严重不良事件（SAE）、去标识化影像/病理引用、盲态隔离、受试者撤回，
以及两周观察窗、可评估状态和结局全程溯源。

## 模块

- `trial.py`：纯领域模块（线程安全的内存注册中心 `TrialRegistry`），不含网络与持久化。
- `service.py`：HTTP 入口，`GET /health` 健康检查 + `POST/GET /api/...` 受控接口。
- `test_trial.py`：45 项领域规则测试，含六名受试者并发集成场景。
- `test_api.py`：HTTP 契约测试；`service_contract.py`：健康入口回归。
- `fixtures/domain.json`：受控词表（角色、状态、活动与结局枚举）。

## 运行

```bash
python3 service.py --check     # 基础配置检查
python3 service.py --port 8000 # 启动服务
npm test                       # 运行全部 Python 测试
python3 -m compileall -q .     # 编译检查全部 Python 模块
```

## 核心受控规则

1. **方案递进闸门**：方案只能 草拟→待安全委员会放行→已放行；只有 DSMB 可放行，
   决议为 继续/暂停入组/终止。未放行方案不能用于入组、给药或照光。
2. **中心资质**：中心须按方案版本取得资质且在有效期内，否则入组被阻止。
3. **同意与入排**：同意书版本必须与入组方案一致；所有入选标准满足且无排除项才可入组。
4. **剂量队列**：队列绑定方案版本，跨方案分配即“剂量混淆”被阻止；禁止重复分配；
   容量并发安全。
5. **批次**：药物/器械批次须合格且在有效期内；隔离、过期、类别错误均被拦截。
6. **操作时间线**：照光必须在完成注射之后，且间隔落在方案窗口（默认 60–240 分钟）；
   实际光剂量必须与队列一致。
7. **器械更换**：以“器械更换”结局关闭失败活动并链接替代活动（失败活动不产生剂量事实，
   可留痕引用故障批次；替代照光成功才开启观察窗）。**术期延后**不构成治疗事实，
   重排时重新过窗校验。
8. **观察窗**：自实际照光完成起 14 天；窗外排程、采集和结局登记一律阻止；
   可评估状态须在观察窗开启后判定。
9. **紧急偏离**：可先行处置——治疗前紧急处置只豁免其声明的那一次活动，
   治疗中方案偏离豁免时序/剂量一致性；其余活动冻结，必须补录原因并经 DSMB 复核。
   SAE 冻结与撤回不可被紧急偏离覆盖。
10. **SAE**：报告即冻结该受试者治疗，直至 DSMB 复核；安全事件并发上报不丢不漏。
11. **影像/病理**：仅存去标识化引用（URI）与 SHA-256 校验值，不存原始内容；
    自由文本中的电话/邮箱/证件号自动打码；支持按校验值核验副本完整性。
12. **盲态**：盲态评价者看不到队列、剂量与治疗时间线，只能读受试者状态、观察窗
    和去标识采集物引用。
13. **撤回**：撤回时刻后停止一切新增研究用途（活动、采集、入组），
    既有记录与法规要求的安全记录（含撤回后的 SAE）保留。
14. **溯源**：每个结局带 provenance 链——获批方案及放行决议、队列实际剂量、
    活动时间线（含器械批次与更换链接）、SAE/偏离与医学决定；另有只增的审计事件流。

## HTTP 接口

所有 `/api` 请求用请求头标识操作者：

```
X-Actor-Id: doc01
X-Actor-Role: investigator   # investigator|coordinator|dsmb|blind_reader|monitor
```

错误响应统一为 `{"error": {"code": "...", "message": "..."}}`：
400 校验错误、401 未标识身份、403 角色无权、404 不存在、409 状态冲突
（`code` 为细粒度业务子码，如 `protocol_not_approved`、`dose_protocol_mismatch`、
`sae_hold`、`outside_window`、`cohort_full`）。

主要写接口（均为 `POST /api/<资源>/<动作>`）：

| 资源 | 动作 |
|---|---|
| protocols | create / submit / approve / retire |
| sites | register / review / change_status |
| subjects | register / consent / withdraw / screen / enroll |
| lots | register / change_status |
| cohorts | create / assign |
| deviations | declare / supplement / review |
| saes | report / review |
| activities | schedule / perform / delay |
| artifacts | register |
| evaluability | set |
| outcomes | record |

读接口：`GET /api/subjects[/{id}[/timeline|/provenance]]`、`GET /api/cohorts`、
`GET /api/audit?target_type=...&target_id=...`（盲态角色自动收窄字段）。
