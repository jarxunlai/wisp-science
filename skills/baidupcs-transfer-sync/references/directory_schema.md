# 百度网盘科研目录管理规范与架构 (/research)

在个人百度网盘中，建议将科研数据与个人通用资源严格解耦：
- 网盘根目录仅保留：`apps/`、`research/`、`/我的资源/`
- 科研数据全面收敛在 `/research` 体系下，保持可用 CLI 进行自动化管理与同步。

---

## 1. `/research` 目录树架构

```plain text
/research
  ├── 00-inbox/                                   # 待分类或临时转存入口
  ├── 01-rawdata/                                 # 原始测序与多组学数据
  │     ├── scrna/                                # 单细胞 counts / h5ad / Seurat RDS / qs
  │     ├── spatial/                              # 空间转录组 (Visium / CosMx / Xenium / MERFISH / Stereo-seq)
  │     ├── metagenome/                           # 宏基因组 rawdata
  │     └── metabolomics/                         # 代谢组表格与 XCMS 数据
  ├── 02-references/                              # 参考基因组与大型数据库
  │     ├── genomes/                              # 基因组 fasta / gtf、Bowtie / STAR 索引
  │     ├── databases/                            # nt、eggNOG、maxmetagenome_db 等
  │     └── TOSICA/                               # 注释模型与先验先导数据
  ├── 03-software/                                # 生物信息软件与环境镜像
  │     ├── biosoft/                              # cellranger 等大型命令行分析套件
  │     ├── containers/                           # docker / singularity 镜像包
  │     ├── flow-cytometry/                       # CytExpert、FlowJo 等流式软件
  │     └── github/                               # GitHub 仓库打包备份
  ├── 04-courses/                                 # 系统性专业课程与资料（例：SP01-重构版本）
  ├── 05-projects/                                # 具体科研课题与论文复现目录 (<project_name>)
  ├── 06-literature/                              # 专业文献、教材电子书与 Zotero 附件备份
  └── 07-personal/                                # 个人照片、备份与非科研资料
```

---

## 2. 归类与归位原则

1. **不可破坏原始归位**：
   - 外部分享转存时，切忌直接保存到网盘根目录堆积；
   - 优先通过临时过渡目录或直接保存后，使用 `BaiduPCS-Go mv` 精准归位到 `/research` 对应子分类。
2. **已有目录增量合并**：
   - 当收到课程或项目的更新版本时，对比子目录差异，仅迁移新增的脚本和数据文件，避免整目录重命名或直接覆盖。
