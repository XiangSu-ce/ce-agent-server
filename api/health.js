// 健康检查接口
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({ ok: true, timestamp: new Date().toISOString() });
}
