import matplotlib.pyplot as plt


def plot_data(data, x_label="byte guess", y_label="# disjoint-vectors"):
    plt.figure(0)
    plt.clf()
    ax = plt.gca()
    ax.set_title("score view")
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.plot(data, "s:", mec='r', label='trace',  drawstyle="steps-post", ms='2.5')
    plt.show()


