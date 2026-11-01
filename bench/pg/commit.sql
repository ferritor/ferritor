-- One durable commit (a WAL flush): the floor under any write.
INSERT INTO bench_commit (v) VALUES ('\x00');
