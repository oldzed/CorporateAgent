# check_db.py
import sqlite3
import os

DB_FILE = "audit.db"


def print_separator(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)


def check_db_exists():
    if not os.path.exists(DB_FILE):
        print(f"[错误] 数据库文件不存在: {DB_FILE}")
        print(f"       当前目录: {os.getcwd()}")
        return False
    size = os.path.getsize(DB_FILE)
    print(f"[信息] 数据库文件: {os.path.abspath(DB_FILE)}")
    print(f"[信息] 文件大小: {size:,} 字节 ({size/1024:.2f} KB)")
    return True


def show_tables(conn):
    print_separator("所有表")
    rows = conn.execute(
        "SELECT name, type FROM sqlite_master "
        "WHERE type IN ('table','index','view') "
        "ORDER BY type, name"
    ).fetchall()
    tables = [r[0] for r in rows if r[1] == "table"]
    indexes = [r[0] for r in rows if r[1] == "index"]
    views = [r[0] for r in rows if r[1] == "view"]

    print(f"\n表 ({len(tables)}):")
    for t in tables:
        print(f"  - {t}")
    print(f"\n索引 ({len(indexes)}):")
    for i in indexes:
        print(f"  - {i}")
    if views:
        print(f"\n视图 ({len(views)}):")
        for v in views:
            print(f"  - {v}")
    return tables


def show_schema(conn, table):
    print_separator(f"表结构: {table}")
    # 建表 SQL
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table,)
    ).fetchone()
    if sql and sql[0]:
        print("\n[建表 SQL]")
        print(sql[0])

    # 列信息
    print("\n[列信息]")
    print(f"{'序号':<5}{'列名':<22}{'类型':<12}{'非空':<6}{'默认值':<20}{'主键'}")
    print("-" * 70)
    for cid, name, ctype, notnull, dflt, pk in conn.execute(
            f"PRAGMA table_info({table})").fetchall():
        print(f"{cid:<5}{name:<22}{ctype or '':<12}"
              f"{'YES' if notnull else 'NO':<6}"
              f"{str(dflt) if dflt is not None else 'NULL':<20}"
              f"{'PK' if pk else ''}")

    # 索引
    print("\n[索引]")
    idx_list = conn.execute(f"PRAGMA index_list({table})").fetchall()
    if not idx_list:
        print("  (无)")
    for seq, idx_name, unique, origin, partial in idx_list:
        cols = conn.execute(f"PRAGMA index_info({idx_name})").fetchall()
        col_names = ", ".join(c[2] for c in cols)
        uniq = "UNIQUE" if unique else ""
        print(f"  - {idx_name} ({col_names}) {uniq}")

    # 外键
    fks = conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
    if fks:
        print("\n[外键]")
        for fk in fks:
            print(f"  - {fk}")

    # 行数
    cnt = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print(f"\n[行数] {cnt}")


def show_sample_data(conn, table, limit=5):
    print_separator(f"样本数据: {table} (最多 {limit} 行)")
    try:
        cur = conn.execute(f"SELECT * FROM {table} LIMIT ?", (limit,))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    except Exception as e:
        print(f"[错误] {e}")
        return

    if not rows:
        print("  (空表)")
        return

    print(f"\n列: {cols}\n")
    for i, row in enumerate(rows, 1):
        print(f"--- 行 {i} ---")
        for col, val in zip(cols, row):
            # 二进制/长文本截断
            if isinstance(val, bytes):
                disp = f"<BLOB {len(val)} bytes>"
                if len(val) <= 64:
                    try:
                        disp += f" {val[:64]!r}"
                    except Exception:
                        pass
            elif isinstance(val, str) and len(val) > 120:
                disp = val[:120] + f"...(共 {len(val)} 字符)"
            else:
                disp = val
            print(f"  {col:<20} = {disp}")
        print()


def show_flows_stats(conn):
    print_separator("flows 表统计")
    try:
        total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        print(f"总记录数: {total}")
        if total == 0:
            return

        print("\n[按 action 分组]")
        for action, cnt in conn.execute(
                "SELECT action, COUNT(*) FROM flows GROUP BY action "
                "ORDER BY COUNT(*) DESC").fetchall():
            print(f"  {action or '(NULL)':<12} : {cnt}")

        print("\n[按 method 分组]")
        for method, cnt in conn.execute(
                "SELECT method, COUNT(*) FROM flows GROUP BY method "
                "ORDER BY COUNT(*) DESC").fetchall():
            print(f"  {method or '(NULL)':<12} : {cnt}")

        print("\n[按 status 分组 Top10]")
        for status, cnt in conn.execute(
                "SELECT status, COUNT(*) FROM flows GROUP BY status "
                "ORDER BY COUNT(*) DESC LIMIT 10").fetchall():
            print(f"  {status} : {cnt}")

        print("\n[Top 10 主机]")
        for host, cnt in conn.execute(
                "SELECT host, COUNT(*) FROM flows GROUP BY host "
                "ORDER BY COUNT(*) DESC LIMIT 10").fetchall():
            print(f"  {host or '(NULL)':<40} : {cnt}")

        print("\n[Top 10 用户]")
        for user, cnt in conn.execute(
                "SELECT username, COUNT(*) FROM flows GROUP BY username "
                "ORDER BY COUNT(*) DESC LIMIT 10").fetchall():
            print(f"  {user or '(NULL)':<20} : {cnt}")

        print("\n[时间范围]")
        row = conn.execute(
            "SELECT MIN(timestamp), MAX(timestamp) FROM flows").fetchone()
        print(f"  最早: {row[0]}")
        print(f"  最新: {row[1]}")

        print("\n[最近 5 条记录]")
        for r in conn.execute(
                "SELECT timestamp, username, method, host, url, status, action "
                "FROM flows ORDER BY id DESC LIMIT 5").fetchall():
            ts, user, method, host, url, status, action = r
            print(f"  [{ts}] {user} {method} {host} "
                  f"{(url or '')[:50]} -> {status} ({action})")

    except Exception as e:
        print(f"[错误] {e}")


def show_sessions_stats(conn):
    print_separator("sessions 表统计")
    try:
        total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        print(f"总记录数: {total}")
        if total == 0:
            return

        print("\n[按 status 分组]")
        for status, cnt in conn.execute(
                "SELECT status, COUNT(*) FROM sessions GROUP BY status"
        ).fetchall():
            print(f"  {status or '(NULL)':<12} : {cnt}")

        print("\n[按 username 分组]")
        for user, cnt in conn.execute(
                "SELECT username, COUNT(*) FROM sessions GROUP BY username "
                "ORDER BY COUNT(*) DESC").fetchall():
            print(f"  {user or '(NULL)':<20} : {cnt}")

        print("\n[按 role 分组]")
        for role, cnt in conn.execute(
                "SELECT role, COUNT(*) FROM sessions GROUP BY role"
        ).fetchall():
            print(f"  {role or '(NULL)':<12} : {cnt}")

        print("\n[use_upstream_proxy 分布]")
        for v, cnt in conn.execute(
                "SELECT COALESCE(use_upstream_proxy,0), COUNT(*) "
                "FROM sessions GROUP BY 1").fetchall():
            print(f"  {'ON' if v else 'OFF':<6} : {cnt}")

        print("\n[当前在线会话]")
        rows = conn.execute(
            "SELECT session_id, username, role, client_ip, login_time, "
            "last_seen, COALESCE(use_upstream_proxy,0) "
            "FROM sessions WHERE status='online' "
            "ORDER BY last_seen DESC").fetchall()
        if not rows:
            print("  (无)")
        for sid, user, role, ip, lt, ls, up in rows:
            print(f"  sid={sid[:12]}...  user={user:<12} role={role or '':<10} "
                  f"ip={ip:<16} login={lt} last={ls} "
                  f"upstream={'ON' if up else 'OFF'}")

    except Exception as e:
        print(f"[错误] {e}")


def main():
    print("=" * 70)
    print("  audit.db 数据库结构检查工具")
    print("=" * 70)

    if not check_db_exists():
        return

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = None
    try:
        tables = show_tables(conn)
        for t in tables:
            show_schema(conn, t)
            show_sample_data(conn, t, limit=3)

        # 专门统计
        if "flows" in tables:
            show_flows_stats(conn)
        if "sessions" in tables:
            show_sessions_stats(conn)

    finally:
        conn.close()

    print("\n" + "=" * 70)
    print("  检查完成")
    print("=" * 70)


if __name__ == "__main__":
    main()