import jwt from "jsonwebtoken";
import "dotenv/config";

export function requireAuth(req, res, next) {
  // Bỏ qua xác thực cho các route đăng ký và đăng nhập
  if (req.path === "/register" || req.path === "/login") {
    return next();
  }

  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  
  if (!m) {
    return res.status(401).json({ message: "Missing token" });
  }
  
  try {
    req.user = jwt.verify(m[1], process.env.JWT_SECRET || "dev_secret");
    next();
  } catch (error) {
    console.error("JWT verification error:", error);
    return res.status(401).json({ message: "Invalid token" });
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    // Cho phép các route public không cần role
    if (req.path === "/register" || req.path === "/login") {
      return next();
    }
    
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };
}