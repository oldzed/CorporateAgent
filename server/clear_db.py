# -*- coding: utf-8 -*-
"""清空 audit.db 中的 flows / sessions 数据，保留表结构与索引。仅用于演示。"""
import os
import sqlite3

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.db")


def main():
    if not os.path.exists(DB_FILE):
        print(f"[错误] 找不到 {DB_FILE}")
        return
    conn = sqlite3.connect(DB_FILE, timeout=5)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        n_flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        n_sess  = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        conn.execute("DELETE FROM flows")
        conn.execute("DELETE FROM sessions")
        conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN ('flows','sessions')")
        conn.commit()
        print(f"[完成] 已删除 flows {n_flows} 条 / sessions {n_sess} 条，"
              f"表结构与索引保留。")
    finally:
        conn.close()


if __name__ == "__main__":
    ans = input("确认清空 audit.db 中 flows 和 sessions 的全部数据？"
                "输入 yes 继续: ").strip().lower()
    if ans == "yes":
        main()
    else:
        print("已取消")