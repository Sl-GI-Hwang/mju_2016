#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>


////////////////////////////////////////////////////////////
// Function : define & static
//=====================================================
// Input :
// Output :
// Purpose : 저장공간 설정, Switch - Case를 쓰기 쉽도록 설정
////////////////////////////////////////////////////////////

#define MAXSIZE BUFSIZ
#define COMMAND 0
#define HALT 1
#define MULTI 2
#define EOL 3
#define PIPE 4
#define CONTINUE 5
#define BACKGROUND 6

static char inbuffer[MAXSIZE];              //입력받은 버퍼 저장
static char *workptr = inbuffer;            //루프를 돌 포인터 정의
static char execute_buffer[MAXSIZE];        //실제로 Data저장, 수행 변형이 일어남
static char *save_char[MAXSIZE];            //Parsing한 Data 저장
static const char delim[] = " &\t;\n\0";    //구분자 저장

static char *cur_path;          //prompt 관련 변수
struct passwd *userinfo;        //prompt 관련 변수

static int statu[MAXSIZE];      //실행중인 process의 status를 저장
static int pids[MAXSIZE];       //실행중인 process의 pid를 저장

sigset_t block_set, new_set;    //signal 관련변수
static int work_num, background_count, status; //Background Mode 관련 변수

// 함수 prototype

void prompt();
void cd();
int scanners();
int process();
int syntax();
int execute(char **args, char flag);
void command_scan(char *i);
void execute_pipe(char *args, int pipe_len);
void close_pipes(int pipes[][2], int count);
void fg();


////////////////////////////////////////////////////////////
// Function : main
//=====================================================
// Input :
// Output :
// Purpose : Signal 설정, Scanner와 Process 실행.
////////////////////////////////////////////////////////////

int main ()
{
    work_num = 1;

    sigemptyset(&block_set);        //signal 제거
    sigaddset(&block_set, SIGINT);  //제거할 signal
    sigaddset(&block_set, SIGQUIT);
    sigaddset(&block_set, SIGKILL);
    sigprocmask(SIG_BLOCK, &block_set, NULL);

    printf("Linux Shell\n");

    while((scanners()) != 0)
    {
         process();
    }

}


////////////////////////////////////////////////////////////
// Function : scanners()
//=====================================================
// Input :
// Output :
// Purpose : prompt 출력. 사용자로부터 명령어를 읽음.
////////////////////////////////////////////////////////////

int scanners () // data input
{
    int count, c;

    // prompt 함수를 부름(함수에서 실행)
    prompt();

    // 저장공간 초기화.
    for(c = 0; c < MAXSIZE; c++)
    {
        execute_buffer[c] = '\0';
        save_char[c] ='\0';
    }

    count = 0;
    while(1)
    {
        // 사용자로부터 명령어를 읽음
        if((c = getchar()) == HALT)
        {
            return HALT;
        }
        // 명령어를 읽어서 버퍼에 저장.
        if(count < MAXSIZE)
        {
            inbuffer[count] = c;
            execute_buffer[count] = c;
        }
        // 엔터만 연타하는 것 Handling
        if( c == '\n' && count == 0)
        {
            inbuffer[count] = '\0';
            count++;
            return count;
        }
        // 명령어를 다 치고 \n이 들어갔을 때에, 배열에 \n을 저장함.
        if( c == '\n' && count < MAXSIZE)
        {
            inbuffer[count] = '\n';
            execute_buffer[count] = '\n';

            // 루프를 돌 Pointer (work Pointer) 설정
            workptr = inbuffer;
            return count;
        }
        count++;
    }
}


////////////////////////////////////////////////////////////
// Function : prompt()
//=====================================================
// Input :
// Output :
// Purpose : prompt 만들기. [userid@path] 형식으로 만들어짐
////////////////////////////////////////////////////////////

void prompt()
{
    // userid를 추출
    userinfo = getpwuid(getuid());
    // current_path를 추출해냄
    cur_path = (char *)getenv("PWD");
    // userid와 current_path를 출력함
    printf("[%s@%s]", userinfo->pw_name, cur_path);
}

////////////////////////////////////////////////////////////
// Function : syntax(char ** inptr)
//=====================================================
// Input : inbuffer[i] <- i는 process에서 증가함
// Output : type <- type은 팔별해낸 문자
// Purpose : prompt 출력. 사용자로부터 명령어를 읽음.
////////////////////////////////////////////////////////////

int syntax()
{
    int type;

    // Work Pointer가 입력 끝까지 돌면서 특수 문자를 판별
    switch(*workptr++)
    {
        case ';':
            type = MULTI;
            break;
        case '\n':
            type = EOL;
            break;
        case '\0':
            type = CONTINUE;
            break;
        case '|':
            type = PIPE;
            break;
        case '&':
            type = BACKGROUND;
            break;
        default:
            type = COMMAND;
            break;

    }

    // 판별한 문자를 리턴.
    return type;

}


////////////////////////////////////////////////////////////
// Function : process()
//=====================================================
// Input :
// Output : syn_type
// Purpose : syntax로 받은 문자열로 각종 명령어를 수행함.
////////////////////////////////////////////////////////////


int process()
{
    char *args[MAXSIZE], buff[MAXSIZE];
    char *stmt;
    int i, point, p, status, j;
    int pipe_count, syn_type;

    i = 0;
    point = 0;
    pipe_count = 0;
    background_count = 0;

    while(1)
    {
        // syntax로부터 값을 읽어들임
        syn_type = syntax();
        switch(syn_type)
        {
            // 일반 명령어를 받으면 point를 증가시킴
            case COMMAND:
                {
                    if(point < MAXSIZE)
                        point++;
                }
                break;
            // \n을 받았을 시에 execute를 수행함.
            case EOL:
                command_scan(execute_buffer);
                // stmt는 cp, ls와 같은 명령어부분을 추출함
                stmt = save_char[0];
                // 맨 처음 문자열이 종료문자열인 halt라면 종료시킴.
                if(strcmp(stmt, "halt") == 0)
                {
                    exit(0);
                    break;
                }
                // fg라면 foreground로 전환
                if(strcmp(stmt, "fg") == 0)
                {
                    fg();
                    break;
                }
                // execvp로 실행할 수 없는 cp라면 별도의 함수로 이동.
                else if(strcmp(stmt, "cd") == 0)
                {
                    cd(save_char);
                    scanners();
                    break;
                }
                // 값이 아예 없다면 다음 값을 읽어들임
                else if(stmt == NULL)
                {
                    scanners();
                    break;
                }
                // signal에서 kill 명령을 받아들이면 kill을 수행
                else if(strcmp(stmt, "kill") == 0)
                {
                    stmt = save_char[1];

                    stmt = strtok(stmt, "-");

                    p = atoi(stmt);
                    j = atoi(save_char[2]);
                    i = 0;
                    while(i < work_num) {
                        if(pids[i] == j)
                        {
                            break;
                        }
                        i++;
                    }
                    kill(j, p);
                    waitpid(j, &statu[i], 0);
                    scanners();
                    break;
                }
                // 일반 execvp로 수행가능한 명령이라면 수행.
                else
                {
                    status = execute(save_char, '\n');
                    break;
                }
                break;

            // 세미콜론으로 분리된 여려 명령어를 처리한다.
            case MULTI:
                if(point !=0)
                {
                    // 초기화
                    for(i = 0;i < MAXSIZE;i++)
                        buff[i] = '\0';

                    // 명령을 수행할 부분을 자름
                    for(i = 0;execute_buffer[i] != ';';i++)
		    {
                        buff[i] = execute_buffer[i];
                    }
                    i++;
                    buff[i] = '\0';

                    command_scan(buff);

                    // stmt는 cp, ls와 같은 명령어부분을 추출함
                    stmt = save_char[0];

                    // 맨 처음 문자열이 종료문자열인 halt라면 종료시킴.
                    if(strcmp(stmt, "halt") == 0)
                    {
                        exit(0);
                        break;
                    }
                    // execvp로 실행할 수 없는 cp라면 별도의 함수로 이동.
                    else if(strcmp(stmt, "cd") == 0)
                    {
                        cd(save_char);
                    }
                    // 일반 execvp로 수행가능한 명령이라면 수행.
                    else
                    {
                        execute(save_char, ';');
                    }

                    // 버퍼 초기화.
                    for(p = 0;p < MAXSIZE;p++)
                        buff[p] = '\0';

                    // 현재 값 삭제하고 다음에 수행할 값을 저장함.
                    for(p = 0;execute_buffer[i] != '\0';p++)
                    {
                        buff[p] = execute_buffer[i];
                        i++;
                    }

                    i = 0;
                    while(i < MAXSIZE)
                    {
                        execute_buffer[i] = buff[i];
                        i++;
                    }
                }
                break;
            // Linux의 Pipe 기능을 지원한다.
            case PIPE:
                if(point !=0)
                {
                    // 초기화
                    pipe_count = 0;

                    // 'I'이라는 글자가 들어올때까지 카운트를 셈
                    for(p = 0; execute_buffer[p] !='|'; p++)
                        pipe_count++;

                    //파이프를 수행함.
                    execute_pipe(execute_buffer, pipe_count);
                }
                break;
            // 명령어를 Background에서 실행하는 기능일 지원한다.
            case BACKGROUND:
                // Background에서 실행하라고 하면, 카운트를 올리고 지나감. 실제 수행은 EOL이나, MULTI에서 수행함.
                background_count++;
                break;

            // 다음으로 검색할 것이  \0 (null)이라면, scanner을 다시실행시켜줌.
            case CONTINUE:
                scanners();
                break;
        }
    }
    return syn_type;

}


////////////////////////////////////////////////////////////
// Function : cd()
//=====================================================
// Input : **args <- 이동하고 싶은 경로
// Output :
// Purpose : linux의 cd기능을 수행함.
////////////////////////////////////////////////////////////

void cd(char **args)
{
    char curpath[BUFSIZ];

    // 현재 경로를 OLDPWD에 저장
    getcwd(curpath, BUFSIZ);
    setenv("OLDPWD", curpath, 1);

    // 새로운 경로로 이동해서 PWD에 저장
    chdir(args[1]);
    getcwd(curpath, BUFSIZ);
    setenv("PWD", curpath, 1);
}


////////////////////////////////////////////////////////////
// Function : command_scan()
//=====================================================
// Input : *in <- 파싱할 문자 string
// Output :
// Purpose : 문자열을 parsing함.
////////////////////////////////////////////////////////////

void command_scan(char *in)
{
    char *result;
    int i;

    // 초기화
    for(i = 0; i<MAXSIZE; i++)
        save_char[i] = '\0';

    // 문자열 분리
    result = strtok(in,delim);

    // 더이상 분리할 수 없을 때까지 분리함.
    for(i = 0; result != NULL; i++)
    {
        save_char[i] = result;
        result = strtok(NULL, delim);
    }
}


////////////////////////////////////////////////////////////
// Function : execute()
//=====================================================
// Input : **args(분리된 문자배열), flag(;에서 왔는지 \n에서 왔는지 판별)
// Output : status (process의 status)
// Purpose : execvp를 이용하여서 읽어들인 명령어를 처리함.
////////////////////////////////////////////////////////////

// 주어진 명령어를 수행함.
int execute(char **args, char flag)
{
    int i, pid;
    int status;

    i = 1;
    // execvp 하면서 종료하는것을 방지하기 위해 fork함
    pid = fork();
    if (pid == 0)
    {
        // 자식 process 안에서 signal을 처리할 수 있게 하기 위해서 signal을 설정함.
        sigaddset(&new_set, SIGINT);
        sigaddset(&new_set, SIGTSTP);
        sigaddset(&new_set, SIGKILL);
        sigprocmask(SIG_UNBLOCK, &new_set, &block_set);

        if(background_count == 1)
        {
            // background 모드에서는 signal을 차단함.
            sigemptyset(&new_set);
            sigaddset(&new_set, SIGINT);
            sigaddset(&new_set, SIGQUIT);
            sigprocmask(SIG_BLOCK, &new_set, NULL);
            // fg를 대비해서 각 process의 pid를 저장
            pids[work_num] = getpid();
            printf("[%d]\t%d\n",work_num, getpid());
        }
        // execvp 함수 실행. 오류가 날 때에는 if문 안에 내용을 수행함.
        if (execvp(args[0], args) < 0)
        {
            perror(args[0]);
            // 다음 prompt 받을때에 세그멘테이션 방지용 초기화
            if(flag == '\n')
            {
                i = 0;
                while(i < MAXSIZE)
                {
                    inbuffer[i] = '\0';
                    execute_buffer[i] = '\0';
                    save_char[i] = '\0';
                    i++;
                }
                workptr = inbuffer;
            }
            exit(0);
        }
    }
    else
    {
        // 다음 prompt 받을때에 세그멘테이션 방지용 초기화
        if(flag == '\n')
        {
            i = 0;
            while(i < MAXSIZE)
            {
                inbuffer[i] = '\0';
                execute_buffer[i] = '\0';
                save_char[i] = '\0';
                i++;
            }
        }
        // background 모드가 아니면 waitpid 수행함.
        if(background_count != 1)
        {
            if(waitpid(pid, &status, 0) == -1)
            {
                return -1;
            }
            return status;
        }
        // background 모드에서는 prompt 출력.
        else
        {
            // fg를 대비해서 각 process의 pid를 저장
            statu[work_num] = status;
            work_num++;
            background_count--;
            return status;
        }
    }
}


////////////////////////////////////////////////////////////
// Function : execute_pipe()
//=====================================================
// Input : *args(분리안한 문자배열), pipe_len(Work Pointer 연산을 위해 필요함)
// Output : status (process의 status)
// Purpose : Linux의 Pipe 기능을 처리함.
////////////////////////////////////////////////////////////

void execute_pipe(char *args, int pipe_len)
{
    FILE *read_fp;

    int status, i, p;
    int index = 0;

    char flag;
    char buff[MAXSIZE];
    char buffer[MAXSIZE];
    char *stmt;

    // 초기화
    for(i = 0;i < MAXSIZE;i++)
        buff[i] = '\0';

    // flag설정. ;에서 왔는지 \n에서 왔는지 판별함.
    for(i = 0;args[i] != '\0'; i++)
    {
        if(args[i] == ';')
            flag = ';';
        else
            flag = '\n';
    }

    // ;가 되었던 \n이 되었던간에 다음 명령어 처리하기전까지 문자를 읽어들임.
    for(i = 0;args[i] != flag;i++)
    {
        buff[i] = args[i];
    }
    i++;
    buff[i] = '\0';

    // 해당 문자열을 stmt에 저장함.
    stmt = buff;
    // pipe 기능 수행.
    memset(buffer, '\0', sizeof(buffer));
    read_fp = popen(stmt, "r");
    if(read_fp != NULL)
    {
        status = fread(buffer, sizeof(char), MAXSIZE, read_fp);
        if (status >0)
            printf("%s", buffer);

        pclose(read_fp);
    }

    // 다음 Work Pointer을 지목하기 위해서
    // Pipe 명령어를 다 수행하고 원래 있어야 할 위치인 i에서
    // 위에서 가져온 Pipe까지의 길이인 pipe_len을 빼주고
    // 그 차이만큼 Work Pointer을 이동시킨다.
    for(p = 0;p < (i- pipe_len); p++)
        *workptr++;

    // flag가 ;인 경우에는 다음 문자열을 저장한다.
    if (flag == ';')
    {
        for(p = 0;p < MAXSIZE;p++)
            buff[p] = '\0';

        for(p = 0;args[i] != '\0';p++)
        {
            buff[p] = args[i];
            i++;
        }

        i = 0;
        while(i < MAXSIZE)
        {
            execute_buffer[i] = buff[i];
            i++;
        }
    }
    // flag가 \n인 경우에는 종료된 것이므로 scanners()을 호출함.
    else
    {
        scanners();
    }
}

////////////////////////////////////////////////////////////
// Function : fg()
//=====================================================
// Input :
// Output :
// Purpose : background process를 foreground로 전환
////////////////////////////////////////////////////////////
void fg()
{
    int i = 0;
    while (i < work_num)
    {
        waitpid(pids[i], &statu[i], 0);
        i++;
    }