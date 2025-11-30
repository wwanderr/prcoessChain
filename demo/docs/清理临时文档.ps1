# 清理临时调试、修复、排查文档
#
# 使用方法：在 demo/docs 目录下运行
#   PowerShell -ExecutionPolicy Bypass -File 清理临时文档.ps1

$docsPath = Split-Path -Parent $MyInvocation.MyCommand.Path

$filesToRemove = @(
    "告警日志判断逻辑修正.md",
    "实体节点排查-调试日志增强.md",
    "实体节点问题-排查指南.md",
    "建图方案-关键映射同步修复.md",
    "断链识别修复-processGuid等于traceId的场景.md",
    "无告警场景-紧急排查.md",
    "无告警场景调试指南.md",
    "日志累积优化实施完成.md",
    "映射关系修复说明.md",
    "晚拆分方案-问题排查指南.md",
    "本次优化总结.md",
    "根节点父节点ID冲突修复说明.md",
    "父进程节点排查-调试日志增强.md",
    "自环性能分析.md",
    "节点日志opType问题修复完成.md",
    "节点日志opType问题排查.md",
    "实体字段赋值修复说明.md",
    "虚拟父进程opType修复说明.md"
)

$removedCount = 0
$notFoundCount = 0

foreach ($file in $filesToRemove) {
    $filePath = Join-Path $docsPath $file
    if (Test-Path $filePath) {
        try {
            Remove-Item $filePath -Force
            Write-Host "✓ 已删除: $file" -ForegroundColor Green
            $removedCount++
        }
        catch {
            Write-Host "✗ 删除失败: $file ($($_.Exception.Message))" -ForegroundColor Red
        }
    }
    else {
        Write-Host "- 不存在: $file" -ForegroundColor Gray
        $notFoundCount++
    }
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "清理完成" -ForegroundColor Cyan
Write-Host "  删除文件数: $removedCount" -ForegroundColor Green
Write-Host "  未找到: $notFoundCount" -ForegroundColor Gray
Write-Host "===============================================" -ForegroundColor Cyan


