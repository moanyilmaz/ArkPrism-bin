# ArkPrism

## 环境

- JDK 21+
- Maven 3.6+
- WSL + Python 3.8+ + angr（可选，只分析.so时需要）

需要下载华为内部文件：

1. **angr** (Python库，用于.so分析)
   - 下载: https://cmc.centralrepo.rnd.huawei.com/artifactory/pypi-central-repo/angr/9.2.124rc0+h1.cbgcloud.appgallery.r14/
   - 文件: `angr-9.2.124rc0+h1.cbgcloud.appgallery.r14-py3-none-manylinux2014_x86_64.whl`
   - WSL中安装: `pip3 install angr-9.2.124rc0+h1.cbgcloud.appgallery.r14-py3-none-manylinux2014_x86_64.whl`

2. **hisec-enhance-app-analyzer-all-in-one** (Java库)
   - 从内部Maven仓库下载 `hisec-enhance-app-analyzer-all-in-one-26.0.0.21.jar`
   - 放到项目根目录 `lib/` 文件夹下

## 编译

1. 把 `settings.xml` 复制到 `~/.m2/` 覆盖
2. 确保 `lib/hisec-enhance-app-analyzer-all-in-one-26.0.0.21.jar` 已存在
3. `mvn clean compile -DskipTests`

## 运行

```bash
mvn exec:java -Dexec.mainClass="com.huawei.hisec.Main"
```

输入放 `input/` 目录，结果输出到 `out/` 目录。

## 配置

配置文件在 `config/` 目录：
- `privacy_apis.json` - ArkTS API 规则
- `native_privacy_apis.json` - Native API 规则
- `profile_combinations.json` - 多源组合规则

### 高级选项

在 `PreciseSensitiveApiScanner.java` 中可以调整以下开关：

```java
private static final boolean ENABLE_SSA = false;  // 是否启用 SSA 变换
```

- **ENABLE_SSA = false**（默认）：跳过 SSA 变换
- **ENABLE_SSA = true**：启用 SSA 变换，可获得更精确的 def-use 分析，但性能开销较大

## 常见问题

Q: 报 `Could not initialize class com.huawei.hianalyzer.utils.FileUtil`
A: pom.xml 里加上 slf4j 依赖：
```xml
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>1.7.36</version>
</dependency>
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-simple</artifactId>
    <version>1.7.36</version>
</dependency>
```

Q: .so 扫描失败
A: WSL 安装 angr ：将 `angr/pure_angr_scanner.py` 复制到 `~/arkprism/`