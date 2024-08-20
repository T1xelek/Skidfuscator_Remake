package dev.skidfuscator.obfuscator.transform.impl.string;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.event.annotation.Listen;
import dev.skidfuscator.obfuscator.event.impl.transform.method.RunMethodTransformEvent;
import dev.skidfuscator.obfuscator.event.impl.transform.skid.PostSkidTransformEvent;
import dev.skidfuscator.obfuscator.skidasm.SkidClassNode;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;
import dev.skidfuscator.obfuscator.skidasm.cfg.SkidBlock;
import dev.skidfuscator.obfuscator.skidasm.expr.SkidConstantExpr;
import dev.skidfuscator.obfuscator.transform.AbstractTransformer;
import dev.skidfuscator.obfuscator.transform.Transformer;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.EncryptionGeneratorV3;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.v3.ByteBufferClinitV3EncryptionGenerator;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.v3.BytesClinitV3EncryptionGenerator;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.v3.BytesV3EncryptionGenerator;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.polymorphic.PolymorphicEncryptionGenerator;
import dev.skidfuscator.obfuscator.util.RandomUtil;
import org.mapleir.asm.ClassNode;
import org.mapleir.ir.cfg.ControlFlowGraph;
import org.mapleir.ir.code.CodeUnit;
import org.mapleir.ir.code.Expr;

import java.util.*;
import java.util.stream.Collectors;

public class StringTransformerV2 extends AbstractTransformer {
    private final Map<SkidClassNode, EncryptionGeneratorV3> keyMap = new HashMap<>();

    private final Set<String> INJECTED = new HashSet<>();

    public StringTransformerV2(Skidfuscator skidfuscator) {
        this(skidfuscator, Collections.emptyList());
    }

    public StringTransformerV2(Skidfuscator skidfuscator, List<Transformer> children) {
        super(skidfuscator, "String Encryption", children);
    }

    @Listen
    void handle(final RunMethodTransformEvent event) {
        final SkidMethodNode methodNode = event.getMethodNode();

        if (methodNode.isAbstract()
                || methodNode.isInit()) {
            this.skip();
            return;
        }

        if (methodNode.node.instructions.size() > 10000) {
            this.fail();
            return;
        }

        final ControlFlowGraph cfg = methodNode.getCfg();

        if (cfg == null) {
            this.fail();
            return;
        }

        cfg.recomputeEdges();

        final PolymorphicEncryptionGenerator generator = new PolymorphicEncryptionGenerator(skidfuscator);
        cfg.allExprStream()
                /*
                 *
                 */
                .filter(SkidConstantExpr.class::isInstance)
                .map(SkidConstantExpr.class::cast)
                .filter(e -> !e.isExempt())
                .filter(constantExpr -> constantExpr.getConstant() instanceof String)
                /*
                 * We collect since we're modifying the expression stream
                 * we kinda need to just not cause any concurrency issue.
                 * ¯\_(ツ)_/¯
                 */
                .collect(Collectors.toList())
                .forEach(unit -> {
                    final CodeUnit parent = unit.getParent();
                    final Expr modified = generator.encrypt(
                            unit,
                            methodNode,
                            unit.getBlock()
                    );

                    try {
                        parent.overwrite(unit, encrypted);
                    } catch (IllegalStateException e) {
                        return;
                    }
                });
        this.success();
    }
}
