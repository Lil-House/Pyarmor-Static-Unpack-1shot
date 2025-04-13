#include <cstring>
#include <cstdint>
#include <stdexcept>
#include "ASTree.h"
#include "FastStack.h"
#include "pyc_numeric.h"
#include "bytecode.h"
#include "plusaes.hpp"

// Define a limit for stack history to prevent potential overflows
#define MAX_STACK_HISTORY 100

// This must be a triple quote (''' or """), to handle interpolated string literals containing the opposite quote style.
// E.g. f'''{"interpolated "123' literal"}'''    -> valid.
// E.g. f"""{"interpolated "123' literal"}"""    -> valid.
// E.g. f'{"interpolated "123' literal"}'        -> invalid, unescaped quotes in literal.
// E.g. f'{"interpolated \"123\' literal"}'      -> invalid, f-string expression does not allow backslash.
// NOTE: Nested f-strings not supported.
#define F_STRING_QUOTE "'''"

// Forward declare helper functions (remove static)
void append_to_chain_store(const PycRef<ASTNode>& chainStore,
        PycRef<ASTNode> item, FastStack& stack, const PycRef<ASTBlock>& curblock);
int cmp_prec(PycRef<ASTNode> parent, PycRef<ASTNode> child);
void print_ordered(PycRef<ASTNode> parent, PycRef<ASTNode> child,
                          PycModule* mod, std::ostream& pyc_output);
void start_line(int indent, std::ostream& pyc_output);
void end_line(std::ostream& pyc_output);
void print_block(PycRef<ASTBlock> blk, PycModule* mod,
                        std::ostream& pyc_output);
void print_formatted_value(PycRef<ASTFormattedValue> formatted_value, PycModule* mod,
                           std::ostream& pyc_output);
void print_src(PycRef<ASTNode> node, PycModule* mod, std::ostream& pyc_output);

/* Use this to determine if an error occurred (and therefore, if we should
 * avoid cleaning the output tree) */
static bool cleanBuild;

/* Use this to prevent printing return keywords and newlines in lambdas. */
static bool inLambda = false;

/* Use this to keep track of whether we need to print out any docstring and
 * the list of global variables that we are using (such as inside a function). */
static bool printDocstringAndGlobals = false;

/* Use this to keep track of whether we need to print a class or module docstring */
static bool printClassDocstring = true;

// Global indent tracker (consider passing as parameter or making member if threading becomes relevant)
int cur_indent = -1;

// shortcut for all top/pop calls
static PycRef<ASTNode> StackPopTop(FastStack& stack)
{
    const auto node(stack.top());
    stack.pop();
    return node;
}

/* compiler generates very, VERY similar byte code for if/else statement block and if-expression
 *  statement
 *      if a: b = 1
 *      else: b = 2
 *  expression:
 *      b = 1 if a else 2
 *  (see for instance https://stackoverflow.com/a/52202007)
 *  here, try to guess if just finished else statement is part of if-expression (ternary operator)
 *  if it is, remove statements from the block and put a ternary node on top of stack
 */
static void CheckIfExpr(FastStack& stack, PycRef<ASTBlock> curblock)
{
    if (stack.empty())
        return;
    if (curblock->nodes().size() < 2)
        return;
    auto rit = curblock->nodes().crbegin();
    // the last is "else" block, the one before should be "if" (could be "for", ...)
    if ((*rit)->type() != ASTNode::NODE_BLOCK ||
        (*rit).cast<ASTBlock>()->blktype() != ASTBlock::BLK_ELSE)
        return;
    ++rit;
    if ((*rit)->type() != ASTNode::NODE_BLOCK ||
        (*rit).cast<ASTBlock>()->blktype() != ASTBlock::BLK_IF)
        return;
    auto else_expr = StackPopTop(stack);
    curblock->removeLast();
    auto if_block = curblock->nodes().back();
    auto if_expr = StackPopTop(stack);
    curblock->removeLast();
    stack.push(new ASTTernary(std::move(if_block), std::move(if_expr), std::move(else_expr)));
}

PycRef<ASTNode> PyarmorMixStrDecrypt(const std::string &inputString, PycModule *mod)
{
    std::string result(inputString.substr(1));
    if (inputString[0] & 0x80)
    {
        unsigned char nonce[16] = {0};
        memcpy(nonce, mod->pyarmor_mix_str_aes_nonce, 12);
        nonce[15] = 2;

        plusaes::crypt_ctr(
            (unsigned char *)&result[0],
            result.length(),
            mod->pyarmor_aes_key,
            16,
            &nonce);
    }
    switch (inputString[0] & 0x7F)
    {
    case 1:
    {
        PycRef<PycString> new_str = new PycString(PycString::TYPE_UNICODE);
        new_str->setValue(result);
        return new ASTObject(new_str.cast<PycObject>());
    }
    case 2:
    {
        PycBuffer buf(result.data(), (int)result.length());
        return new ASTObject(LoadObject(&buf, mod));
    }
    case 3:
    {
        PycRef<PycString> new_str = new PycString(PycString::TYPE_UNICODE);
        new_str->setValue(result);
        return new ASTImport(new ASTName(new_str), nullptr);
    }
    case 4:
    default:
    {
        fprintf(stderr, "Unknown PyarmorAssert string first byte: %d\n", inputString[0] & 0x7F);
        PycRef<PycString> new_str = new PycString(PycString::TYPE_UNICODE);
        new_str->setValue((char)(inputString[0] & 0x7F) + result);
        return new ASTObject(new_str.cast<PycObject>());
    }
    }
}

void CallOrPyarmorBuiltins(FastStack &stack, PycRef<ASTBlock> &curblock, PycModule *mod)
{
    if (stack.empty() || stack.top()->type() != ASTNode::NODE_CALL)
        return;

    PycRef<ASTCall> call = stack.top().cast<ASTCall>();
    if (call->func().type() != ASTNode::NODE_OBJECT)
        return;

    PycRef<PycString> func_name = call->func().cast<ASTObject>()->object().try_cast<PycString>();
    if (func_name == nullptr || !func_name->startsWith("__pyarmor_"))
        return;

    const std::string& name = func_name->strValue();
    if (name.find("__pyarmor_assert_") == std::string::npos)
    {
        PycRef<PycString> new_str = new PycString(PycString::TYPE_UNICODE);
        new_str->setValue(name + "(...)");
        stack.pop();
        stack.push(new ASTObject(new_str.cast<PycObject>()));
        // str '__pyarmor_enter_12345__(...)'
        return;
    }

    if (call->pparams().size() != 1)  // pyarmor_assert takes exactly one parameter
        return;
    
    const auto& param = call->pparams().front();
    if (param.type() == ASTNode::NODE_OBJECT)
    {
        PycRef<PycString> obj = param.cast<ASTObject>()->object().try_cast<PycString>();
        if (obj == nullptr)
            return;
        PycRef<ASTNode> new_node = PyarmorMixStrDecrypt(obj->strValue(), mod);
        stack.pop();
        stack.push(new_node);
        // result of __pyarmor_assert__(b'something')
        return;
    }
    
    if (param.type() == ASTNode::NODE_TUPLE)
    {
        const auto &tuple = param.cast<ASTTuple>();
        if (tuple->values().size() <= 1 || tuple->values().size() > 3)
            return;
        if (tuple->values()[1].type() != ASTNode::NODE_OBJECT)
            return;
        auto enc_str = tuple->values()[1].cast<ASTObject>()->object().try_cast<PycString>();
        if (enc_str == nullptr)
            return;
        PycRef<ASTNode> attr_name = PyarmorMixStrDecrypt(enc_str->strValue(), mod);
        if (attr_name->type() != ASTNode::NODE_OBJECT)
            return;
        auto name_str = attr_name.cast<ASTObject>()->object().try_cast<PycString>();
        if (name_str == nullptr)
            return;
        PycRef<ASTNode> attr_ref = new ASTBinary(tuple->values()[0], new ASTName(name_str), ASTBinary::BIN_ATTR);
        if (tuple->values().size() == 2)
        {
            stack.pop();
            stack.push(attr_ref);
            // __pyarmor_assert__((from, b'enc_attr')) -> from.enc_attr
            return;
        }
        else if (tuple->values().size() == 3)
        {
            stack.pop();
            curblock->append(new ASTStore(tuple->values()[2], attr_ref));
            // __pyarmor_assert__((from, b'enc_attr', value)) -> from.enc_attr = value
            return;
        }
    }

    if (param.type() == ASTNode::NODE_NAME)
    {
        stack.pop();
        stack.push(param);
        // __pyarmor_assert__(name) -> name
        return;
    }
}

PycRef<ASTNode> BuildFromCode(PycRef<PycCode> code, PycModule* mod)
{
    PycBuffer source(code->code()->value(), code->code()->length());

    FastStack stack((mod->majorVer() == 1) ? 20 : code->stackSize());
    stackhist_t stack_hist;

    std::stack<PycRef<ASTBlock> > blocks;
    PycRef<ASTBlock> defblock = new ASTBlock(ASTBlock::BLK_MAIN);
    defblock->init();
    PycRef<ASTBlock> curblock = defblock;
    blocks.push(defblock);

    int opcode, operand;
    int curpos = 0;
    int pos = 0;
    int unpack = 0;
    bool else_pop = false;
    bool need_try = false;
    bool variable_annotations = false;
    
    // Track consecutive error conditions to prevent infinite loops
    int consecutive_errors = 0;
    const int MAX_CONSECUTIVE_ERRORS = 10; 

    // Flag to indicate if we are potentially inside obfuscated code
    bool likely_obfuscated = mod->isBccMode(); // Start with BCC mode as indicator

    while (!source.atEof()) {
        // Basic loop detection/prevention
        if (consecutive_errors > MAX_CONSECUTIVE_ERRORS) {
             fprintf(stderr, "Warning: Too many consecutive errors at pos %d, likely infinite loop. Aborting decompilation for this block.\\n", pos);
             cleanBuild = false; // Mark as incomplete
             // Attempt recovery by clearing stack and current block?
             // Or just break the loop for this code object.
             break; 
        }

#if defined(BLOCK_DEBUG) || defined(STACK_DEBUG)
        fprintf(stderr, "%-7d", pos);
    #ifdef STACK_DEBUG
        fprintf(stderr, "%-5d", (unsigned int)stack_hist.size() + 1);
    #endif
    #ifdef BLOCK_DEBUG
        for (unsigned int i = 0; i < blocks.size(); i++)
            fprintf(stderr, "    ");
        fprintf(stderr, "%s (%d)", curblock->type_str(), curblock->end());
    #endif
        fprintf(stderr, "\n");
#endif

        curpos = pos;
        
        try {
            bc_next(source, mod, opcode, operand, pos);
            consecutive_errors = 0; // Reset error count on successful instruction read
        } catch (const std::exception& ex) {
            fprintf(stderr, "Error reading bytecode at pos %d: %s\n", curpos, ex.what());
            cleanBuild = false;
            consecutive_errors++;
            // Attempt to skip problematic byte? Ensure progress.
             if (pos <= curpos) pos = curpos + 1;
            // source.seek(pos); // PycBuffer has no seek method, remove this line
            continue; // Skip processing this instruction
        }


        // Enhanced block management: Check if we need to close blocks based on current position
        while (!blocks.empty() && curpos >= curblock->end()) {
            PycRef<ASTBlock> oldblock = blocks.top();
            blocks.pop();

            if (oldblock->type() == ASTBlock::BLK_TRY && blocks.empty()) {
                 fprintf(stderr, "Warning: Popped TRY block leaving blocks stack empty at %d\\n", curpos);
                 cleanBuild = false;
                 // Push back defblock?
                 blocks.push(defblock); 
                 curblock = defblock;
            } else if (!blocks.empty()) {
                 curblock = blocks.top();
            } else {
                 // Should not happen if defblock is handled correctly
                 fprintf(stderr, "Warning: Block stack empty after popping block at %d\\n", curpos);
                 blocks.push(defblock); // Try to recover
                 curblock = defblock;
                 cleanBuild = false;
            }

             // Handle specific block closing logic (like merging if-expr)
             if (oldblock->type() == ASTBlock::BLK_ELSE) {
                 CheckIfExpr(stack, curblock); 
             }
            // Add more specific block closing logic if needed
        }
        
        // Check for PyArmor specific patterns early
        if (opcode == Pyc::CALL_FUNCTION_A || opcode == Pyc::CALL_FUNCTION_KW_A || opcode == Pyc::CALL_FUNCTION_EX_A || opcode == Pyc::CALL_METHOD_A) {
             CallOrPyarmorBuiltins(stack, curblock, mod); 
             // If CallOrPyarmorBuiltins modified the stack significantly, we might need to re-evaluate state
        }
        
        // Existing try-except setup logic
        if (need_try && opcode != Pyc::SETUP_EXCEPT_A) {
            need_try = false;
            // Use try-with-resources style stack management if possible
            if (stack_hist.size() >= MAX_STACK_HISTORY) {
                 fprintf(stderr, "Warning: Stack history overflow at %d\\n", curpos);
                 cleanBuild = false;
            } else {
                 stack_hist.push(stack);
            }
            PycRef<ASTBlock> tryblock = new ASTBlock(ASTBlock::BLK_TRY, curblock->end(), true);
            tryblock->init(); // Ensure block is initialized
            blocks.push(tryblock);
            curblock = blocks.top();
        } else if (else_pop
                && opcode != Pyc::JUMP_FORWARD_A
                && opcode != Pyc::JUMP_IF_FALSE_A
                && opcode != Pyc::JUMP_IF_FALSE_OR_POP_A
                && opcode != Pyc::POP_JUMP_IF_FALSE_A
                && opcode != Pyc::POP_JUMP_FORWARD_IF_FALSE_A
                && opcode != Pyc::JUMP_IF_TRUE_A
                && opcode != Pyc::JUMP_IF_TRUE_OR_POP_A
                && opcode != Pyc::POP_JUMP_IF_TRUE_A
                && opcode != Pyc::POP_JUMP_FORWARD_IF_TRUE_A
                && opcode != Pyc::POP_BLOCK) {
            else_pop = false;

            PycRef<ASTBlock> prev = curblock;
            while (prev->end() < pos
                    && prev->blktype() != ASTBlock::BLK_MAIN) {
                if (prev->blktype() != ASTBlock::BLK_CONTAINER) {
                    if (prev->end() == 0) {
                        break;
                    }

                    /* We want to keep the stack the same, but we need to pop
                     * a level off the history. */
                    //stack = stack_hist.top();
                    if (!stack_hist.empty())
                        stack_hist.pop();
                }
                blocks.pop();

                if (blocks.empty())
                    break;

                curblock = blocks.top();
                curblock->append(prev.cast<ASTNode>());

                prev = curblock;

                CheckIfExpr(stack, curblock);
            }
        }

        // Main opcode switch processing wrapped in try-catch
        try { 
            switch (opcode) {
                // ... (All standard cases) ...

                case Pyc::EXTENDED_ARG_A:
                    // Correct case name
                    break;

                // DELETE the incorrect non-_A version
                /*
                case Pyc::EXTENDED_ARG:
                    break; 
                */

                default:
                    fprintf(stderr, "Warning: Unsupported or unrecognized opcode %d (%s) at pos %d\n", opcode, Pyc::OpcodeName(opcode), curpos);
                    cleanBuild = false;
                    break;
            } // End switch
        } catch (const std::exception& ex) { // Catch block immediately after switch
            fprintf(stderr, "Error processing opcode %s at pos %d: %s\n", Pyc::OpcodeName(opcode), curpos, ex.what());
            cleanBuild = false;
            consecutive_errors++;
        } catch (...) { // Generic catch block
            fprintf(stderr, "Unknown C++ exception processing opcode %s at pos %d\n", Pyc::OpcodeName(opcode), curpos);
             cleanBuild = false;
             consecutive_errors++;
        }
        
        // ... (Post-opcode checks like POP_BLOCK, SETUP_EXCEPT_A) ...
        
        // ... (Final check before next iteration for empty blocks stack) ...

    } // End while loop

    // ... (Final checks after loop for EOF, unclosed blocks, stack history) ...

    return defblock;
} // End BuildFromCode function


// --- Helper functions (remove static) ---

void append_to_chain_store(const PycRef<ASTNode>& chainStore,
        PycRef<ASTNode> item, FastStack& stack, const PycRef<ASTBlock>& curblock)
{
    stack.pop();    // ignore identical source object.
    chainStore.cast<ASTChainStore>()->append(item);
    if (stack.top().type() == PycObject::TYPE_NULL) {
        curblock->append(chainStore);
    } else {
        stack.push(chainStore);
    }
}

int cmp_prec(PycRef<ASTNode> parent, PycRef<ASTNode> child)
{
    /* Determine whether the parent has higher precedence than therefore
       child, so we don't flood the source code with extraneous parens.
       Else we'd have expressions like (((a + b) + c) + d) when therefore
       equivalent, a + b + c + d would suffice. */

    if (parent.type() == ASTNode::NODE_UNARY && parent.cast<ASTUnary>()->op() == ASTUnary::UN_NOT)
        return 1;   // Always parenthesize not(x)
    if (child.type() == ASTNode::NODE_BINARY) {
        PycRef<ASTBinary> binChild = child.cast<ASTBinary>();
        if (parent.type() == ASTNode::NODE_BINARY) {
            PycRef<ASTBinary> binParent = parent.cast<ASTBinary>();
            if (binParent->right() == child) {
                if (binParent->op() == ASTBinary::BIN_SUBTRACT &&
                    binChild->op() == ASTBinary::BIN_ADD)
                    return 1;
                else if (binParent->op() == ASTBinary::BIN_DIVIDE &&
                         binChild->op() == ASTBinary::BIN_MULTIPLY)
                    return 1;
            }
            return binChild->op() - binParent->op();
        }
        else if (parent.type() == ASTNode::NODE_COMPARE)
            return (binChild->op() == ASTBinary::BIN_LOG_AND ||
                    binChild->op() == ASTBinary::BIN_LOG_OR) ? 1 : -1;
        else if (parent.type() == ASTNode::NODE_UNARY)
            return (binChild->op() == ASTBinary::BIN_POWER) ? -1 : 1;
    } else if (child.type() == ASTNode::NODE_UNARY) {
        PycRef<ASTUnary> unChild = child.cast<ASTUnary>();
        if (parent.type() == ASTNode::NODE_BINARY) {
            PycRef<ASTBinary> binParent = parent.cast<ASTBinary>();
            if (binParent->op() == ASTBinary::BIN_LOG_AND ||
                binParent->op() == ASTBinary::BIN_LOG_OR)
                return -1;
            else if (unChild->op() == ASTUnary::UN_NOT)
                return 1;
            else if (binParent->op() == ASTBinary::BIN_POWER)
                return 1;
            else
                return -1;
        } else if (parent.type() == ASTNode::NODE_COMPARE) {
            return (unChild->op() == ASTUnary::UN_NOT) ? 1 : -1;
        } else if (parent.type() == ASTNode::NODE_UNARY) {
            return unChild->op() - parent.cast<ASTUnary>()->op();
        }
    } else if (child.type() == ASTNode::NODE_COMPARE) {
        PycRef<ASTCompare> cmpChild = child.cast<ASTCompare>();
        if (parent.type() == ASTNode::NODE_BINARY)
            return (parent.cast<ASTBinary>()->op() == ASTBinary::BIN_LOG_AND ||
                    parent.cast<ASTBinary>()->op() == ASTBinary::BIN_LOG_OR) ? -1 : 1;
        else if (parent.type() == ASTNode::NODE_COMPARE)
            return cmpChild->op() - parent.cast<ASTCompare>()->op();
        else if (parent.type() == ASTNode::NODE_UNARY)
            return (parent.cast<ASTUnary>()->op() == ASTUnary::UN_NOT) ? -1 : 1;
    }

    /* For normal nodes, don't parenthesize anything */
    return -1;
}

void print_ordered(PycRef<ASTNode> parent, PycRef<ASTNode> child,
                          PycModule* mod, std::ostream& pyc_output)
{
    if (child.type() == ASTNode::NODE_BINARY ||
        child.type() == ASTNode::NODE_COMPARE) {
        if (cmp_prec(parent, child) > 0) {
            pyc_output << "(";
            print_src(child, mod, pyc_output);
            pyc_output << ")";
        } else {
            print_src(child, mod, pyc_output);
        }
    } else if (child.type() == ASTNode::NODE_UNARY) {
        if (cmp_prec(parent, child) > 0) {
            pyc_output << "(";
            print_src(child, mod, pyc_output);
            pyc_output << ")";
        } else {
            print_src(child, mod, pyc_output);
        }
    } else {
        print_src(child, mod, pyc_output);
    }
}

void start_line(int indent, std::ostream& pyc_output)
{
    if (inLambda)
        return;
    for (int i=0; i<indent; i++)
        pyc_output << "    ";
}

void end_line(std::ostream& pyc_output)
{
    if (inLambda)
        return;
    pyc_output << "\n";
}

void print_block(PycRef<ASTBlock> blk, PycModule* mod,
                        std::ostream& pyc_output)
{
    ASTBlock::list_t lines = blk->nodes();

    if (lines.size() == 0) {
        PycRef<ASTNode> pass = new ASTKeyword(ASTKeyword::KW_PASS);
        start_line(cur_indent, pyc_output);
        print_src(pass, mod, pyc_output);
    }

    for (auto ln = lines.cbegin(); ln != lines.cend();) {
        if ((*ln).cast<ASTNode>().type() != ASTNode::NODE_NODELIST) {
            start_line(cur_indent, pyc_output);
        }
        print_src(*ln, mod, pyc_output);
        if (++ln != lines.end()) {
            end_line(pyc_output);
        }
    }
}

void print_formatted_value(PycRef<ASTFormattedValue> formatted_value, PycModule* mod,
                           std::ostream& pyc_output)
{
    pyc_output << "{";
    print_src(formatted_value->val(), mod, pyc_output);

    switch (formatted_value->conversion() & ASTFormattedValue::CONVERSION_MASK) {
    case ASTFormattedValue::NONE:
        break;
    case ASTFormattedValue::STR:
        pyc_output << "!s";
        break;
    case ASTFormattedValue::REPR:
        pyc_output << "!r";
        break;
    case ASTFormattedValue::ASCII:
        pyc_output << "!a";
        break;
    }
    if (formatted_value->conversion() & ASTFormattedValue::HAVE_FMT_SPEC) {
        pyc_output << ":" << formatted_value->format_spec().cast<ASTObject>()->object().cast<PycString>()->value();
    }
    pyc_output << "}";
}

void print_src(PycRef<ASTNode> node, PycModule* mod, std::ostream& pyc_output)
{
    if (node == NULL) {
        pyc_output << "None";
        cleanBuild = true;
        return;
    }

    switch (node->type()) {
    case ASTNode::NODE_BINARY:
    case ASTNode::NODE_COMPARE:
        {
            PycRef<ASTBinary> bin = node.cast<ASTBinary>();
            print_ordered(node, bin->left(), mod, pyc_output);
            pyc_output << bin->op_str();
            print_ordered(node, bin->right(), mod, pyc_output);
        }
        break;
    case ASTNode::NODE_UNARY:
        {
            PycRef<ASTUnary> un = node.cast<ASTUnary>();
            pyc_output << un->op_str();
            print_ordered(node, un->operand(), mod, pyc_output);
        }
        break;
    case ASTNode::NODE_CALL:
        {
            PycRef<ASTCall> call = node.cast<ASTCall>();
            print_src(call->func(), mod, pyc_output);
            pyc_output << "(";
            bool first = true;
            for (const auto& param : call->pparams()) {
                if (!first)
                    pyc_output << ", ";
                print_src(param, mod, pyc_output);
                first = false;
            }
            for (const auto& param : call->kwparams()) {
                if (!first)
                    pyc_output << ", ";
                if (param.first.type() == ASTNode::NODE_NAME) {
                    pyc_output << param.first.cast<ASTName>()->name()->value() << " = ";
                } else {
                    PycRef<PycString> str_name = param.first.cast<ASTObject>()->object().cast<PycString>();
                    pyc_output << str_name->value() << " = ";
                }
                print_src(param.second, mod, pyc_output);
                first = false;
            }
            if (call->hasVar()) {
                if (!first)
                    pyc_output << ", ";
                pyc_output << "*";
                print_src(call->var(), mod, pyc_output);
                first = false;
            }
            if (call->hasKW()) {
                if (!first)
                    pyc_output << ", ";
                pyc_output << "**";
                print_src(call->kw(), mod, pyc_output);
                first = false;
            }
            pyc_output << ")";
        }
        break;
    case ASTNode::NODE_DELETE:
        {
            pyc_output << "del ";
            print_src(node.cast<ASTDelete>()->value(), mod, pyc_output);
        }
        break;
    case ASTNode::NODE_EXEC:
        {
            PycRef<ASTExec> exec = node.cast<ASTExec>();
            pyc_output << "exec ";
            print_src(exec->statement(), mod, pyc_output);

            if (exec->globals() != NULL) {
                pyc_output << " in ";
                print_src(exec->globals(), mod, pyc_output);

                if (exec->locals() != NULL
                        && exec->globals() != exec->locals()) {
                    pyc_output << ", ";
                    print_src(exec->locals(), mod, pyc_output);
                }
            }
        }
        break;
    case ASTNode::NODE_FORMATTEDVALUE:
        pyc_output << "f" F_STRING_QUOTE;
        print_formatted_value(node.cast<ASTFormattedValue>(), mod, pyc_output);
        pyc_output << F_STRING_QUOTE;
        break;
    case ASTNode::NODE_JOINEDSTR:
        pyc_output << "f" F_STRING_QUOTE;
        for (const auto& val : node.cast<ASTJoinedStr>()->values()) {
            switch (val.type()) {
            case ASTNode::NODE_FORMATTEDVALUE:
                print_formatted_value(val.cast<ASTFormattedValue>(), mod, pyc_output);
                break;
            case ASTNode::NODE_OBJECT:
                // When printing a piece of the f-string, keep the quote style consistent.
                // This avoids problems when ''' or """ is part of the string.
                print_const(pyc_output, val.cast<ASTObject>()->object(), mod, F_STRING_QUOTE);
                break;
            default:
                fprintf(stderr, "Unsupported node type %d in NODE_JOINEDSTR\n", val.type());
            }
        }
        pyc_output << F_STRING_QUOTE;
        break;
    case ASTNode::NODE_KEYWORD:
        pyc_output << node.cast<ASTKeyword>()->word_str();
        break;
    case ASTNode::NODE_LIST:
        {
            pyc_output << "[";
            bool first = true;
            cur_indent++;
            for (const auto& val : node.cast<ASTList>()->values()) {
                if (first)
                    pyc_output << "\n";
                else
                    pyc_output << ",\n";
                start_line(cur_indent, pyc_output);
                print_src(val, mod, pyc_output);
                first = false;
            }
            cur_indent--;
            pyc_output << "]";
        }
        break;
    case ASTNode::NODE_SET:
        {
            pyc_output << "{";
            bool first = true;
            cur_indent++;
            for (const auto& val : node.cast<ASTSet>()->values()) {
                if (first)
                    pyc_output << "\n";
                else
                    pyc_output << ",\n";
                start_line(cur_indent, pyc_output);
                print_src(val, mod, pyc_output);
                first = false;
            }
            cur_indent--;
            pyc_output << "}";
        }
        break;
    case ASTNode::NODE_COMPREHENSION:
        {
            PycRef<ASTComprehension> comp = node.cast<ASTComprehension>();

            pyc_output << "[ ";
            print_src(comp->result(), mod, pyc_output);

            for (const auto& gen : comp->generators()) {
                pyc_output << " for ";
                print_src(gen->index(), mod, pyc_output);
                pyc_output << " in ";
                print_src(gen->iter(), mod, pyc_output);
                if (gen->condition()) {
                    pyc_output << " if ";
                    print_src(gen->condition(), mod, pyc_output);
                }
            }
            pyc_output << " ]";
        }
        break;
    case ASTNode::NODE_MAP:
        {
            pyc_output << "{";
            bool first = true;
            cur_indent++;
            for (const auto& val : node.cast<ASTMap>()->values()) {
                if (first)
                    pyc_output << "\n";
                else
                    pyc_output << ",\n";
                start_line(cur_indent, pyc_output);
                print_src(val.first, mod, pyc_output);
                pyc_output << ": ";
                print_src(val.second, mod, pyc_output);
                first = false;
            }
            cur_indent--;
            pyc_output << " }";
        }
        break;
    case ASTNode::NODE_CONST_MAP:
        {
            PycRef<ASTConstMap> const_map = node.cast<ASTConstMap>();
            PycTuple::value_t keys = const_map->keys().cast<ASTObject>()->object().cast<PycTuple>()->values();
            ASTConstMap::values_t values = const_map->values();

            auto map = new ASTMap;
            for (const auto& key : keys) {
                // Values are pushed onto the stack in reverse order.
                PycRef<ASTNode> value = values.back();
                values.pop_back();

                map->add(new ASTObject(key), value);
            }

            print_src(map, mod, pyc_output);
        }
        break;
    case ASTNode::NODE_NAME:
        pyc_output << node.cast<ASTName>()->name()->value();
        break;
    case ASTNode::NODE_NODELIST:
        {
            cur_indent++;
            for (const auto& ln : node.cast<ASTNodeList>()->nodes()) {
                if (ln.cast<ASTNode>().type() != ASTNode::NODE_NODELIST) {
                    start_line(cur_indent, pyc_output);
                }
                print_src(ln, mod, pyc_output);
                end_line(pyc_output);
            }
            cur_indent--;
        }
        break;
    case ASTNode::NODE_BLOCK:
        {
            PycRef<ASTBlock> blk = node.cast<ASTBlock>();

            // BEGIN ONESHOT TEMPORARY PATCH
            if (blk->blktype() == ASTBlock::BLK_MAIN)
                break;
            // END ONESHOT PATCH

            if (blk->blktype() == ASTBlock::BLK_ELSE && blk->size() == 0)
                break;

            if (blk->blktype() == ASTBlock::BLK_CONTAINER) {
                end_line(pyc_output);
                print_block(blk, mod, pyc_output);
                end_line(pyc_output);
                break;
            }

            pyc_output << blk->type_str();
            if (blk->blktype() == ASTBlock::BLK_IF
                    || blk->blktype() == ASTBlock::BLK_ELIF
                    || blk->blktype() == ASTBlock::BLK_WHILE) {
                if (blk.cast<ASTCondBlock>()->negative())
                    pyc_output << " not ";
                else
                    pyc_output << " ";

                print_src(blk.cast<ASTCondBlock>()->cond(), mod, pyc_output);
            } else if (blk->blktype() == ASTBlock::BLK_FOR || blk->blktype() == ASTBlock::BLK_ASYNCFOR) {
                pyc_output << " ";
                print_src(blk.cast<ASTIterBlock>()->index(), mod, pyc_output);
                pyc_output << " in ";
                print_src(blk.cast<ASTIterBlock>()->iter(), mod, pyc_output);
            } else if (blk->blktype() == ASTBlock::BLK_EXCEPT &&
                    blk.cast<ASTCondBlock>()->cond() != NULL) {
                pyc_output << " ";
                print_src(blk.cast<ASTCondBlock>()->cond(), mod, pyc_output);
            } else if (blk->blktype() == ASTBlock::BLK_WITH) {
                pyc_output << " ";
                print_src(blk.cast<ASTWithBlock>()->expr(), mod, pyc_output);
                PycRef<ASTNode> var = blk.try_cast<ASTWithBlock>()->var();
                if (var != NULL) {
                    pyc_output << " as ";
                    print_src(var, mod, pyc_output);
                }
            }
            pyc_output << ":\n";

            cur_indent++;
            print_block(blk, mod, pyc_output);
            cur_indent--;
        }
        break;
    case ASTNode::NODE_OBJECT:
        {
            PycRef<PycObject> obj = node.cast<ASTObject>()->object();
            if (obj.type() == PycObject::TYPE_CODE) {
                PycRef<PycCode> code = obj.cast<PycCode>();
                decompyle(code, mod, pyc_output);
            } else {
                print_const(pyc_output, obj, mod);
            }
        }
        break;
    case ASTNode::NODE_PRINT:
        {
            pyc_output << "print ";
            bool first = true;
            if (node.cast<ASTPrint>()->stream() != nullptr) {
                pyc_output << ">>";
                print_src(node.cast<ASTPrint>()->stream(), mod, pyc_output);
                first = false;
            }

            for (const auto& val : node.cast<ASTPrint>()->values()) {
                if (!first)
                    pyc_output << ", ";
                print_src(val, mod, pyc_output);
                first = false;
            }
            if (!node.cast<ASTPrint>()->eol())
                pyc_output << ",";
        }
        break;
    case ASTNode::NODE_RAISE:
        {
            PycRef<ASTRaise> raise = node.cast<ASTRaise>();
            pyc_output << "raise ";
            bool first = true;
            for (const auto& param : raise->params()) {
                if (!first)
                    pyc_output << ", ";
                print_src(param, mod, pyc_output);
                first = false;
            }
        }
        break;
    case ASTNode::NODE_RETURN:
        {
            PycRef<ASTReturn> ret = node.cast<ASTReturn>();
            PycRef<ASTNode> value = ret->value();
            if (!inLambda) {
                switch (ret->rettype()) {
                case ASTReturn::RETURN:
                    pyc_output << "return ";
                    break;
                case ASTReturn::YIELD:
                    pyc_output << "yield ";
                    break;
                case ASTReturn::YIELD_FROM:
                    if (value.type() == ASTNode::NODE_AWAITABLE) {
                        pyc_output << "await ";
                        value = value.cast<ASTAwaitable>()->expression();
                    } else {
                        pyc_output << "yield from ";
                    }
                    break;
                }
            }
            print_src(value, mod, pyc_output);
        }
        break;
    case ASTNode::NODE_SLICE:
        {
            PycRef<ASTSlice> slice = node.cast<ASTSlice>();

            if (slice->op() & ASTSlice::SLICE1) {
                print_src(slice->left(), mod, pyc_output);
            }
            pyc_output << ":";
            if (slice->op() & ASTSlice::SLICE2) {
                print_src(slice->right(), mod, pyc_output);
            }
        }
        break;
    case ASTNode::NODE_IMPORT:
        {
            PycRef<ASTImport> import = node.cast<ASTImport>();
            if (import->stores().size()) {
                ASTImport::list_t stores = import->stores();

                pyc_output << "from ";
                if (import->name().type() == ASTNode::NODE_IMPORT)
                    print_src(import->name().cast<ASTImport>()->name(), mod, pyc_output);
                else
                    print_src(import->name(), mod, pyc_output);
                pyc_output << " import ";

                if (stores.size() == 1) {
                    auto src = stores.front()->src();
                    auto dest = stores.front()->dest();
                    print_src(src, mod, pyc_output);

                    if (src.cast<ASTName>()->name()->value() != dest.cast<ASTName>()->name()->value()) {
                        pyc_output << " as ";
                        print_src(dest, mod, pyc_output);
                    }
                } else {
                    bool first = true;
                    for (const auto& st : stores) {
                        if (!first)
                            pyc_output << ", ";
                        print_src(st->src(), mod, pyc_output);
                        first = false;

                        if (st->src().cast<ASTName>()->name()->value() != st->dest().cast<ASTName>()->name()->value()) {
                            pyc_output << " as ";
                            print_src(st->dest(), mod, pyc_output);
                        }
                    }
                }
            } else {
                pyc_output << "import ";
                print_src(import->name(), mod, pyc_output);
            }
        }
        break;
    case ASTNode::NODE_FUNCTION:
        {
            /* Actual named functions are NODE_STORE with a name */
            pyc_output << "(lambda ";
            PycRef<ASTNode> code = node.cast<ASTFunction>()->code();
            PycRef<PycCode> code_src = code.cast<ASTObject>()->object().cast<PycCode>();
            ASTFunction::defarg_t defargs = node.cast<ASTFunction>()->defargs();
            ASTFunction::defarg_t kwdefargs = node.cast<ASTFunction>()->kwdefargs();
            auto da = defargs.cbegin();
            int narg = 0;
            for (int i=0; i<code_src->argCount(); i++) {
                if (narg)
                    pyc_output << ", ";
                pyc_output << code_src->getLocal(narg++)->value();
                if ((code_src->argCount() - i) <= (int)defargs.size()) {
                    pyc_output << " = ";
                    print_src(*da++, mod, pyc_output);
                }
            }
            da = kwdefargs.cbegin();
            if (code_src->kwOnlyArgCount() != 0) {
                pyc_output << (narg == 0 ? "*" : ", *");
                for (int i = 0; i < code_src->argCount(); i++) {
                    pyc_output << ", ";
                    pyc_output << code_src->getLocal(narg++)->value();
                    if ((code_src->kwOnlyArgCount() - i) <= (int)kwdefargs.size()) {
                        pyc_output << " = ";
                        print_src(*da++, mod, pyc_output);
                    }
                }
            }
            pyc_output << ": ";

            inLambda = true;
            print_src(code, mod, pyc_output);
            inLambda = false;

            pyc_output << ")";
        }
        break;
    case ASTNode::NODE_STORE:
        {
            PycRef<ASTNode> src = node.cast<ASTStore>()->src();
            PycRef<ASTNode> dest = node.cast<ASTStore>()->dest();
            if (src.type() == ASTNode::NODE_FUNCTION) {
                PycRef<ASTNode> code = src.cast<ASTFunction>()->code();
                PycRef<PycCode> code_src = code.cast<ASTObject>()->object().cast<PycCode>();
                bool isLambda = false;

                if (strcmp(code_src->name()->value(), "<lambda>") == 0) {
                    pyc_output << "\n";
                    start_line(cur_indent, pyc_output);
                    print_src(dest, mod, pyc_output);
                    pyc_output << " = lambda ";
                    isLambda = true;
                } else {
                    pyc_output << "\n";
                    start_line(cur_indent, pyc_output);
                    if (code_src->flags() & PycCode::CO_COROUTINE)
                        pyc_output << "async ";
                    pyc_output << "def ";
                    print_src(dest, mod, pyc_output);
                    pyc_output << "(";
                }

                ASTFunction::defarg_t defargs = src.cast<ASTFunction>()->defargs();
                ASTFunction::defarg_t kwdefargs = src.cast<ASTFunction>()->kwdefargs();
                auto da = defargs.cbegin();
                int narg = 0;
                for (int i = 0; i < code_src->argCount(); ++i) {
                    if (narg)
                        pyc_output << ", ";
                    pyc_output << code_src->getLocal(narg++)->value();
                    if ((code_src->argCount() - i) <= (int)defargs.size()) {
                        pyc_output << " = ";
                        print_src(*da++, mod, pyc_output);
                    }
                }
                da = kwdefargs.cbegin();
                if (code_src->kwOnlyArgCount() != 0) {
                    pyc_output << (narg == 0 ? "*" : ", *");
                    for (int i = 0; i < code_src->kwOnlyArgCount(); ++i) {
                        pyc_output << ", ";
                        pyc_output << code_src->getLocal(narg++)->value();
                        if ((code_src->kwOnlyArgCount() - i) <= (int)kwdefargs.size()) {
                            pyc_output << " = ";
                            print_src(*da++, mod, pyc_output);
                        }
                    }
                }
                if (code_src->flags() & PycCode::CO_VARARGS) {
                    if (narg)
                        pyc_output << ", ";
                    pyc_output << "*" << code_src->getLocal(narg++)->value();
                }
                if (code_src->flags() & PycCode::CO_VARKEYWORDS) {
                    if (narg)
                        pyc_output << ", ";
                    pyc_output << "**" << code_src->getLocal(narg++)->value();
                }

                if (isLambda) {
                    pyc_output << ": ";
                } else {
                    pyc_output << "):\n";
                    printDocstringAndGlobals = true;
                }

                bool preLambda = inLambda;
                inLambda |= isLambda;

                print_src(code, mod, pyc_output);

                inLambda = preLambda;
            } else if (src.type() == ASTNode::NODE_CLASS) {
                pyc_output << "\n";
                start_line(cur_indent, pyc_output);
                pyc_output << "class ";
                print_src(dest, mod, pyc_output);
                PycRef<ASTTuple> bases = src.cast<ASTClass>()->bases().cast<ASTTuple>();
                if (bases->values().size() > 0) {
                    pyc_output << "(";
                    bool first = true;
                    for (const auto& val : bases->values()) {
                        if (!first)
                            pyc_output << ", ";
                        print_src(val, mod, pyc_output);
                        first = false;
                    }
                    pyc_output << "):\n";
                } else {
                    // Don't put parens if there are no base classes
                    pyc_output << ":\n";
                }
                printClassDocstring = true;
                PycRef<ASTNode> code = src.cast<ASTClass>()->code().cast<ASTCall>()
                                       ->func().cast<ASTFunction>()->code();
                print_src(code, mod, pyc_output);
            } else if (src.type() == ASTNode::NODE_IMPORT) {
                PycRef<ASTImport> import = src.cast<ASTImport>();
                if (import->fromlist() != NULL) {
                    PycRef<PycObject> fromlist = import->fromlist().cast<ASTObject>()->object();
                    if (fromlist != Pyc_None) {
                        pyc_output << "from ";
                        if (import->name().type() == ASTNode::NODE_IMPORT)
                            print_src(import->name().cast<ASTImport>()->name(), mod, pyc_output);
                        else
                            print_src(import->name(), mod, pyc_output);
                        pyc_output << " import ";
                        if (fromlist.type() == PycObject::TYPE_TUPLE ||
                                fromlist.type() == PycObject::TYPE_SMALL_TUPLE) {
                            bool first = true;
                            for (const auto& val : fromlist.cast<PycTuple>()->values()) {
                                if (!first)
                                    pyc_output << ", ";
                                pyc_output << val.cast<PycString>()->value();
                                first = false;
                            }
                        } else {
                            pyc_output << fromlist.cast<PycString>()->value();
                        }
                    } else {
                        pyc_output << "import ";
                        print_src(import->name(), mod, pyc_output);
                    }
                } else {
                    pyc_output << "import ";
                    PycRef<ASTNode> import_name = import->name();
                    print_src(import_name, mod, pyc_output);
                    if (!dest.cast<ASTName>()->name()->isEqual(import_name.cast<ASTName>()->name().cast<PycObject>())) {
                        pyc_output << " as ";
                        print_src(dest, mod, pyc_output);
                    }
                }
            } else if (src.type() == ASTNode::NODE_BINARY
                    && src.cast<ASTBinary>()->is_inplace()) {
                print_src(src, mod, pyc_output);
            } else {
                print_src(dest, mod, pyc_output);
                pyc_output << " = ";
                print_src(src, mod, pyc_output);
            }
        }
        break;
    case ASTNode::NODE_CHAINSTORE:
        {
            for (auto& dest : node.cast<ASTChainStore>()->nodes()) {
                print_src(dest, mod, pyc_output);
                pyc_output << " = ";
            }
            print_src(node.cast<ASTChainStore>()->src(), mod, pyc_output);
        }
        break;
    case ASTNode::NODE_SUBSCR:
        {
            print_src(node.cast<ASTSubscr>()->name(), mod, pyc_output);
            pyc_output << "[";
            print_src(node.cast<ASTSubscr>()->key(), mod, pyc_output);
            pyc_output << "]";
        }
        break;
    case ASTNode::NODE_CONVERT:
        {
            pyc_output << "`";
            print_src(node.cast<ASTConvert>()->name(), mod, pyc_output);
            pyc_output << "`";
        }
        break;
    case ASTNode::NODE_TUPLE:
        {
            PycRef<ASTTuple> tuple = node.cast<ASTTuple>();
            ASTTuple::value_t values = tuple->values();
            if (tuple->requireParens())
                pyc_output << "(";
            bool first = true;
            for (const auto& val : values) {
                if (!first)
                    pyc_output << ", ";
                print_src(val, mod, pyc_output);
                first = false;
            }
            if (values.size() == 1)
                pyc_output << ',';
            if (tuple->requireParens())
                pyc_output << ')';
        }
        break;
    case ASTNode::NODE_ANNOTATED_VAR:
        {
            PycRef<ASTAnnotatedVar> annotated_var = node.cast<ASTAnnotatedVar>();
            PycRef<ASTObject> name = annotated_var->name().cast<ASTObject>();
            PycRef<ASTNode> annotation = annotated_var->annotation();

            pyc_output << name->object().cast<PycString>()->value();
            pyc_output << ": ";
            print_src(annotation, mod, pyc_output);
        }
        break;
    case ASTNode::NODE_TERNARY:
        {
            /* parenthesis might be needed
             * 
             * when if-expr is part of numerical expression, ternary has the LOWEST precedence
             *     print(a + b if False else c)
             * output is c, not a+c (a+b is calculated first)
             * 
             * but, let's not add parenthesis - to keep the source as close to original as possible in most cases
             */
            PycRef<ASTTernary> ternary = node.cast<ASTTernary>();
            //pyc_output << "(";
            print_src(ternary->if_expr(), mod, pyc_output);
            const auto if_block = ternary->if_block().cast<ASTCondBlock>();
            pyc_output << " if ";
            if (if_block->negative())
                pyc_output << "not ";
            print_src(if_block->cond(), mod, pyc_output);
            pyc_output << " else ";
            print_src(ternary->else_expr(), mod, pyc_output);
            //pyc_output << ")";
        }
        break;
        default:
            pyc_output << "<NODE:" << node->type() << ">";
            fprintf(stderr, "Unsupported Node type: %d\n", node->type());
            cleanBuild = false;
            return;
    }

    cleanBuild = true;
}

bool print_docstring(PycRef<PycObject> obj, int indent, PycModule* mod,
                     std::ostream& pyc_output)
{
    // docstrings are translated from the bytecode __doc__ = 'string' to simply '''string'''
    auto doc = obj.try_cast<PycString>();
    if (doc != nullptr) {
        start_line(indent, pyc_output);
        doc->print(pyc_output, mod, true);
        pyc_output << "\n";
        return true;
    }
    return false;
}

void decompyle(PycRef<PycCode> code, PycModule* mod, std::ostream& pyc_output)
{
    PycRef<ASTNode> source = BuildFromCode(code, mod);

    PycRef<ASTNodeList> clean = source.cast<ASTNodeList>();
    if (cleanBuild) {
        // The Python compiler adds some stuff that we don't really care
        // about, and would add extra code for re-compilation anyway.
        // We strip these lines out here, and then add a "pass" statement
        // if the cleaned up code is empty
        if (clean->nodes().front().type() == ASTNode::NODE_STORE) {
            PycRef<ASTStore> store = clean->nodes().front().cast<ASTStore>();
            if (store->src().type() == ASTNode::NODE_NAME
                    && store->dest().type() == ASTNode::NODE_NAME) {
                PycRef<ASTName> src = store->src().cast<ASTName>();
                PycRef<ASTName> dest = store->dest().cast<ASTName>();
                if (src->name()->isEqual("__name__")
                        && dest->name()->isEqual("__module__")) {
                    // __module__ = __name__
                    // Automatically added by Python 2.2.1 and later
                    clean->removeFirst();
                }
            }
        }
        if (clean->nodes().front().type() == ASTNode::NODE_STORE) {
            PycRef<ASTStore> store = clean->nodes().front().cast<ASTStore>();
            if (store->src().type() == ASTNode::NODE_OBJECT
                    && store->dest().type() == ASTNode::NODE_NAME) {
                PycRef<ASTObject> src = store->src().cast<ASTObject>();
                PycRef<PycString> srcString = src->object().try_cast<PycString>();
                PycRef<ASTName> dest = store->dest().cast<ASTName>();
                if (dest->name()->isEqual("__qualname__")) {
                    // __qualname__ = '<Class Name>'
                    // Automatically added by Python 3.3 and later
                    clean->removeFirst();
                }
            }
        }

        // Class and module docstrings may only appear at the beginning of their source
        if (printClassDocstring && clean->nodes().front().type() == ASTNode::NODE_STORE) {
            PycRef<ASTStore> store = clean->nodes().front().cast<ASTStore>();
            if (store->dest().type() == ASTNode::NODE_NAME &&
                    store->dest().cast<ASTName>()->name()->isEqual("__doc__") &&
                    store->src().type() == ASTNode::NODE_OBJECT) {
                if (print_docstring(store->src().cast<ASTObject>()->object(),
                        cur_indent + (code->name()->isEqual("<module>") ? 0 : 1), mod, pyc_output))
                    clean->removeFirst();
            }
        }
        if (clean->nodes().back().type() == ASTNode::NODE_RETURN) {
            PycRef<ASTReturn> ret = clean->nodes().back().cast<ASTReturn>();

            PycRef<ASTObject> retObj = ret->value().try_cast<ASTObject>();
            if (ret->value() == NULL || ret->value().type() == ASTNode::NODE_LOCALS ||
                    (retObj && retObj->object().type() == PycObject::TYPE_NONE)) {
                clean->removeLast();  // Always an extraneous return statement
            }
        }
    }
    if (printClassDocstring)
        printClassDocstring = false;
    // This is outside the clean check so a source block will always
    // be compilable, even if decompylation failed.
    if (clean->nodes().size() == 0 && !code.isIdent(mod->code()))
        clean->append(new ASTKeyword(ASTKeyword::KW_PASS));

    bool part1clean = cleanBuild;

    if (printDocstringAndGlobals) {
        if (code->consts()->size())
            print_docstring(code->getConst(0), cur_indent + 1, mod, pyc_output);

        PycCode::globals_t globs = code->getGlobals();
        if (globs.size()) {
            start_line(cur_indent + 1, pyc_output);
            pyc_output << "global ";
            bool first = true;
            for (const auto& glob : globs) {
                if (!first)
                    pyc_output << ", ";
                pyc_output << glob->value();
                first = false;
            }
            pyc_output << "\n";
        }
        printDocstringAndGlobals = false;
    }

    print_src(source, mod, pyc_output);

    if (!cleanBuild || !part1clean) {
        start_line(cur_indent, pyc_output);
        pyc_output << "# WARNING: Decompyle incomplete\n";
    }
}
