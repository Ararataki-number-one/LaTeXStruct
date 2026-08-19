from concurrent.futures import ThreadPoolExecutor

import pytest

from latexstruct.server import downloads


def test_safe_download_filename_removes_paths_reserved_names_and_invalid_characters():
    assert downloads.safe_download_filename(r"..\CON.tex") == "_CON.tex"
    assert downloads.safe_download_filename('章一：定理?.tex') == "章一：定理_.tex"
    assert downloads.safe_download_filename("../") == "LaTeXStruct-result.tex"


def test_save_unique_download_never_overwrites(tmp_path):
    first = downloads.save_unique_download(b"first", "result.tex", root=tmp_path)
    second = downloads.save_unique_download(b"second", "result.tex", root=tmp_path)

    assert first == tmp_path / "result.tex"
    assert second == tmp_path / "result (1).tex"
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"second"


def test_concurrent_downloads_all_get_unique_complete_files(tmp_path):
    payloads = [f"copy-{index}".encode() for index in range(12)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        paths = list(pool.map(
            lambda payload: downloads.save_unique_download(payload, "result.tex", root=tmp_path),
            payloads,
        ))

    assert len({path.name for path in paths}) == len(payloads)
    assert {path.read_bytes() for path in paths} == set(payloads)


def test_save_unique_download_retries_transient_windows_replace_denial(tmp_path, monkeypatch):
    original_replace = downloads.os.replace
    attempts = 0

    def transient_replace(source, destination):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(5, "transient scanner lock")
        return original_replace(source, destination)

    monkeypatch.setattr(downloads.os, "name", "nt")
    monkeypatch.setattr(downloads.os, "replace", transient_replace)
    monkeypatch.setattr(downloads.time, "sleep", lambda _seconds: None)

    saved = downloads.save_unique_download(b"complete", "result.tex", root=tmp_path)

    assert attempts == 2
    assert saved.read_bytes() == b"complete"


def test_managed_download_root_rejects_link(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("当前 Windows 环境不允许创建测试符号链接")

    with pytest.raises(OSError, match="链接|Junction"):
        downloads.save_unique_download(b"no", "result.tex", root=linked)
    assert list(real.iterdir()) == []


def test_save_unique_download_removes_partial_file_on_write_failure(tmp_path, monkeypatch):
    original_fsync = downloads.os.fsync

    def fail_fsync(_fd):
        raise OSError("disk full")

    monkeypatch.setattr(downloads.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="disk full"):
        downloads.save_unique_download(b"partial", "result.tex", root=tmp_path)
    monkeypatch.setattr(downloads.os, "fsync", original_fsync)
    assert list(tmp_path.iterdir()) == []


def test_reveal_only_selects_existing_file_inside_fixed_root(tmp_path, monkeypatch):
    saved = tmp_path / "safe.tex"
    saved.write_text("ok", encoding="utf-8")
    calls = []
    monkeypatch.setattr(downloads.subprocess, "Popen", lambda command, **kwargs: calls.append((command, kwargs)))

    folder = downloads.reveal_download_location("../safe.tex", root=tmp_path)

    assert folder == tmp_path
    assert len(calls) == 1
    command = calls[0][0]
    assert str(tmp_path) in " ".join(command)
    assert ".." not in " ".join(command)


def test_reveal_missing_filename_opens_folder(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(downloads.subprocess, "Popen", lambda command, **kwargs: calls.append(command))

    downloads.reveal_download_location("missing.tex", root=tmp_path)

    assert len(calls) == 1
    assert str(tmp_path) in " ".join(calls[0])
