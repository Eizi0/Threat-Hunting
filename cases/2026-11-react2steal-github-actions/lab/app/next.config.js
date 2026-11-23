// LAB_IMAGES=permissive : autorise n'importe quel hôte http (mauvaise configuration à tester)
const permissive = process.env.LAB_IMAGES === 'permissive';
module.exports = permissive
  ? { images: { remotePatterns: [{ protocol: 'http', hostname: '**' }] } }
  : {};
