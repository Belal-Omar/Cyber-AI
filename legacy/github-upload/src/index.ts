import "dotenv/config";
import path from "path";
import express from "express";
import { prisma } from "./lib/prisma";
import authRoutes from "./routes/auth";

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is missing in .env");
}

const app = express();
app.use(express.json());

// يخدم index.html / login.html / signup.html من روت المشروع
app.use(express.static(path.join(__dirname, "..")));

app.get("/api/health", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(500).json({ status: "error", database: "disconnected" });
  }
});

app.use("/api/auth", authRoutes);

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
