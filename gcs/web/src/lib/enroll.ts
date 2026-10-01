/** 登记向导状态机（P0-3）：身份→设备→确认三步；校验与步进为纯函数。
 *
 * 设计要点：初始表单零预填（示例值只能经 SAMPLE_FORM 显式填入——演示便利
 * 不进产品面）；身份证 18 位数字钉定；确认页向用户明示"身份与设备在发行
 * 时刻绑定进同一承诺（换绑须重新登记）"——密码学约束的前端诚实呈现。
 */

export interface EnrollForm {
  username: string;
  id_number: string;
  cert_level: number;
  sn: string;
  class_id: number;
}

/** 初始表单（零预填——红测试钉定）。cert_level 0/class_id -1=未选（0=微型是合法
 * 机型类，不能兼当哨兵；后端 fail-closed 兜底）。 */
export function initialEnrollForm(): EnrollForm {
  return { username: "", id_number: "", cert_level: 0, sn: "", class_id: -1 };
}

/** 演示示例数据（仅经"填入示例"按钮显式进入表单）。 */
export const SAMPLE_FORM: EnrollForm = {
  username: "pilot",
  id_number: "110101199001011234",
  cert_level: 3,
  sn: "FZ-SN-WEB-01",
  class_id: 1,
};

export type EnrollStep = 1 | 2 | 3;

export const ENROLL_STEPS: { n: EnrollStep; title: string; hint: string }[] = [
  { n: 1, title: "身份信息", hint: "仅在本机参与承诺计算，不向服务器提交明文" },
  { n: 2, title: "设备信息", hint: "无人机序列号与机型类（公开广播面）" },
  { n: 3, title: "确认并生成密钥", hint: "本机生成专属密钥对，承诺上链；身份与设备在此绑定，换绑须重新登记" },
];

const ID_NUMBER_RE = /^\d{18}$/;

/** 单步校验：通过返回 null，否则返回错误码（组件映射为提示文案）。
 * step 入参放宽为 number——越界步返回 no_such_step（运行时守卫）。 */
export function validateStep(step: number, f: EnrollForm): string | null {
  if (step === 1) {
    if (!f.username.trim()) return "username_required";
    if (!ID_NUMBER_RE.test(f.id_number)) return "id_number_format";
    return null;
  }
  if (step === 2) {
    if (!f.sn.trim()) return "sn_required";
    if (!Number.isInteger(f.cert_level) || f.cert_level < 1 || f.cert_level > 4)
      return "cert_level_range";
    if (!Number.isInteger(f.class_id) || f.class_id < 0 || f.class_id > 255)
      return "class_id_range";
    return null;
  }  if (step === 3) return null; // 确认页：前两步已校验
  return "no_such_step";
}

/** 密码强度分级：0=空 1=弱 2=中 3=强（长度+字符类别数）——登记密码用于加密本机私钥。 */
export function passphraseStrength(pw: string): 0 | 1 | 2 | 3 {
  if (!pw) return 0;
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  if (pw.length < 8) return 1;
  if (pw.length >= 12 && classes >= 3) return 3;
  if (classes >= 2) return 2;
  return 1;
}

// ---- 账户密码规范（2026-09-29 账户批，队长拍板：8 位起步）----
// 密码=密封体系的唯一人肉防线（登录解封+资料密封同一 KEK 源）——前端门槛与
// 后端 21000 轮 KDF 是同一道防线的两半。黑名单拒绝常见弱密码（离线猜测面
// 的最大贡献者），与用户名相同/包含直接拒。

const WEAK_LIST = [
  "12345678", "123456789", "1234567890", "password", "password1", "qwerty123",
  "11111111", "88888888", "abc12345", "00000000", "12341234", "a1234567",
];

export interface PasswordCheck {
  ok: boolean;
  failures: string[];
  checks: { label: string; pass: boolean }[];
}

export function checkPasswordRules(pw: string, username: string): PasswordCheck {
  const checks = [
    { label: "至少 8 位", pass: pw.length >= 8 },
    { label: "含字母", pass: /[A-Za-z]/.test(pw) },
    { label: "含数字", pass: /[0-9]/.test(pw) },
    { label: "非常见弱密码", pass: !!pw && !WEAK_LIST.includes(pw.toLowerCase()) },
    {
      label: "与用户名不同",
      pass:
        !!pw && !!username &&
        pw.toLowerCase() !== username.toLowerCase() &&
        !pw.toLowerCase().includes(username.toLowerCase()),
    },
  ];
  return {
    ok: checks.every((c) => c.pass),
    failures: checks.filter((c) => !c.pass).map((c) => c.label),
    checks,
  };
}
